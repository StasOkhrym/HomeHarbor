"""Create isolated opt-in sandbox trust and configs without touching dev state."""

import base64
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

import tomlkit
from dev_init import SECRET_BYTES
from private_state import complete
from sandbox_identity import load_public_identity, validate_public_identity
from sandbox_pair import stored_pair_documents
from sandbox_preflight import NETWORK_FILE, PROFILES, load_profile
from tls_material import issue, issue_authority, same_authority, verify_pair
from tooling import ROOT, atomic_write, cli, port, quiet_run, require_commands

SANDBOX = ROOT / ".sandbox"
HOST_CONTROL = "control.localhost"
HOST_RELAY = "relay.localhost"
GATEWAY_CONTROL = "control.sandbox"
GATEWAY_RELAY = "relay.sandbox"


@dataclass(frozen=True)
class EndpointAudience:
    control: str
    relay: str


def endpoint_audience(role: str, https_port: int) -> EndpointAudience:
    if role == "host":
        control, relay = HOST_CONTROL, HOST_RELAY
    elif role == "gateway":
        control, relay = GATEWAY_CONTROL, GATEWAY_RELAY
    else:
        raise ValueError("sandbox endpoint audience must be host or gateway")

    return EndpointAudience(
        control=f"https://{control}:{https_port}",
        relay=f"wss://{relay}:{https_port}/relay/udp",
    )


def check_destination(path: Path) -> None:
    if not path.is_relative_to(SANDBOX):
        raise ValueError("sandbox init may write only its isolated state")

    for parent in (path, *path.parents):
        if parent == ROOT:
            break
        if parent.is_symlink():
            raise ValueError(f"sandbox path contains a symlink: {parent}")


def document(name: str, target: str | None = None):
    path = SANDBOX / f"{target or name}.toml"
    source = path if path.exists() else ROOT / f"config/{name}.example.toml"

    return tomlkit.parse(source.read_text())


def configuration(
    port_number: int,
    selected: dict[str, str] | None = None,
    native_ports: tuple[int, int] | None = None,
) -> dict[Path, tuple[bytes, int]]:
    selected = selected or load_profile()
    host = endpoint_audience("host", port_number)
    gateway = endpoint_audience("gateway", 8443)
    control = document("control")
    control["server"]["public_url"] = host.control
    control["auth"]["rp_id"] = HOST_CONTROL
    control["auth"]["rp_origin"] = host.control
    control["relay"]["public_url"] = host.relay
    control["networking"]["network_id"] = "sandbox-network"
    control["security"]["trusted_proxy_cidrs"] = [selected["SANDBOX_PROXY_BACKEND_IP"] + "/32"]
    relay = document("relay")
    relay["server"]["udp_listen_address"] = ":52000"
    relay["server"]["udp_port_min"] = 52000
    relay["server"]["udp_port_max"] = 52015
    # The authenticated admission Host selects the reachable endpoint for
    # host and container clients; a global advertise host breaks one audience.
    relay["server"]["udp_advertise_host"] = ""
    relay["server"]["udp_advertise_hosts"] = {
        HOST_RELAY: HOST_RELAY,
        GATEWAY_RELAY: "relay",
    }
    agent = document("agent", "gateway")
    agent["node"]["state_path"] = "/var/lib/homeharbor/gateway.json"
    agent["node"]["control_url"] = gateway.control
    agent["node"]["ca_file"] = "/run/secrets/relay_tls_ca"
    agent["relay"]["websocket_url"] = gateway.relay
    agent["wireguard"]["interface"] = "wg0"
    agent["wireguard"]["overlay_address"] = selected["SANDBOX_GATEWAY_OVERLAY_IP"] + "/32"
    # No peer has been enrolled yet. Never inherit the example's fixed peer
    # route, which can point outside the selected overlay profile.
    agent["wireguard"]["allowed_prefixes"] = ""
    agent["relay"]["destination_device_id"] = ""
    agent["coordination"]["url"] = (
        gateway.control.replace("https://", "wss://") + "/api/v1/coordination"
    )
    agent["coordination"]["root_public_key_file"] = "/run/secrets/root_public_key"
    agent["coordination"]["network_id"] = "sandbox-network"
    # Compose owns IPv4 forwarding through its namespaced sysctl. The
    # unprivileged container mount makes /proc/sys read-only at runtime.
    agent["dns"]["enable_forwarding"] = False
    admin = document("admin")
    admin["endpoint"] = host.control
    admin["ca_file"] = str(SANDBOX / "secrets/relay_tls_ca")
    admin["base_url"] = host.control + "/invite"
    admin["network_id"] = "sandbox-network"
    admin["profile_id"] = "sandbox"
    admin["overlay_pool"] = selected["SANDBOX_OVERLAY_SUBNET"]
    admin["root_key_file"] = str(SANDBOX / "root-key.age")
    admin["passphrase_file"] = str(SANDBOX / "root-passphrase")
    admin["snapshot_manifest_file"] = str(SANDBOX / "initial-snapshot.toml")
    admin["invite_attempts_file"] = str(SANDBOX / "invite-attempts.json")
    documents = {
        SANDBOX / f"{name}.toml": (tomlkit.dumps(doc).encode(), 0o600)
        for name, doc in (
            ("control", control),
            ("relay", relay),
            ("gateway", agent),
            ("admin", admin),
        )
    }
    documents.update(
        stored_pair_documents(
            SANDBOX, selected, port_number, os.getuid(), check_destination, native_ports
        )
    )
    return documents


def render_manifest(selected: dict[str, str], gateway: dict[str, str] | None = None) -> bytes:
    template = (ROOT / "deploy/sandbox/initial-snapshot.toml").read_text()
    for original, replacement in (
        ("10.200.0.2", selected["SANDBOX_GATEWAY_OVERLAY_IP"]),
        ("172.29.50.0/24", selected["SANDBOX_PRIVATE_SUBNET"]),
        ("172.29.50.53", selected["SANDBOX_DNS_IP"]),
        ("172.29.50.80", selected["SANDBOX_SITE_IP"]),
    ):
        template = template.replace(original, replacement)
    if gateway is None:
        return template.encode()
    gateway = validate_public_identity(gateway)
    manifest = tomlkit.parse(template)
    device = manifest["devices"][0]
    previous_id = device["id"]
    device["id"] = gateway["device_id"]
    device["identity_public_key"] = gateway["identity_public_key"]
    device["wireguard_public_key"] = gateway["wireguard_public_key"]
    for item in manifest["gateways"]:
        if item["device_id"] == previous_id:
            item["device_id"] = gateway["device_id"]
    for item in manifest["routes"]:
        if item["gateway_id"] == previous_id:
            item["gateway_id"] = gateway["device_id"]
    for item in manifest["profiles"]:
        item["device_ids"] = [
            gateway["device_id"] if value == previous_id else value for value in item["device_ids"]
        ]
    for item in manifest["acl"]:
        if item["source_device_id"] == previous_id:
            item["source_device_id"] = gateway["device_id"]
    return tomlkit.dumps(manifest).encode()


def legacy_manifest_without_acl(selected: dict[str, str]) -> bytes:
    """Recognize only the exact earlier generated fixture for safe migration."""

    prefix = render_manifest(selected).decode().split("\n[[acl]]", 1)[0]
    prefix = prefix.replace(
        'acl_rule_ids = ["sandbox-dns-udp", "sandbox-dns-tcp", "sandbox-site-web"]',
        "acl_rule_ids = []",
    )

    return prefix.encode()


def resolve_manifest(
    existing: bytes | None, selected: dict[str, str], gateway: dict[str, str] | None
) -> bytes:
    desired = render_manifest(selected, gateway)
    migratable = {
        render_manifest(selected),
        render_manifest(PROFILES[0].environment()),
        legacy_manifest_without_acl(PROFILES[0].environment()),
        legacy_manifest_without_acl(selected),
    }
    # The former unsigned fixture could never pass HTTPS-only snapshot
    # validation. Recognize only exact generated documents, preserving any
    # operator-edited identity, ACL, URL or profile for explicit review.
    migratable.update(
        candidate.replace(
            b'url = "https://site.sandbox.home.arpa:8080"',
            b'url = "http://site.sandbox.home.arpa:8080"',
        )
        for candidate in (*migratable, desired)
    )
    if existing is None or existing == desired or existing in migratable:
        return desired

    raise ValueError(
        "existing sandbox manifest differs from selected profile or enrolled gateway; review it before replacing"
    )


def gateway_public_identity() -> dict[str, str] | None:
    path = SANDBOX / "gateway-public.json"
    check_destination(path)
    return load_public_identity(path)


def initialize() -> None:
    require_commands("openssl")
    if not NETWORK_FILE.is_file():
        raise ValueError("run sandbox preflight before initialization")

    selected = load_profile()
    https_port = port(os.environ.get("SANDBOX_HTTPS_PORT", "8443"), "SANDBOX_HTTPS_PORT")
    pending = configuration(https_port, selected)
    secret_dir = SANDBOX / "secrets"
    ca, ca_key = secret_dir / "relay_tls_ca", SANDBOX / "relay-ca-key.pem"
    relay_cert, relay_key = secret_dir / "relay_tls_cert", secret_dir / "relay_tls_key"
    front_cert, front_key = secret_dir / "frontend_tls_cert", secret_dir / "frontend_tls_key"
    site_cert, site_key = secret_dir / "site_tls_cert", secret_dir / "site_tls_key"
    site_ca, site_ca_key = secret_dir / "site_tls_ca", SANDBOX / "site-ca-key.pem"
    root_key, root_public = SANDBOX / "root-key.age", SANDBOX / "root-public.key"
    passphrase, mounted_root = SANDBOX / "root-passphrase", secret_dir / "root_public_key"
    has_relay = complete([ca, ca_key, relay_cert, relay_key], "Sandbox relay TLS")
    has_front = complete([front_cert, front_key], "Sandbox frontend TLS")
    has_site = complete([site_ca, site_ca_key, site_cert, site_key], "Sandbox private site TLS")
    has_root = complete([root_key, root_public, passphrase, mounted_root], "Sandbox root")
    for name, size in SECRET_BYTES.items():
        path = secret_dir / name
        if path.exists():
            content = path.read_bytes()
            if len(content) != ((size + 2) // 3) * 4:
                raise ValueError(f"sandbox secret {name} has an invalid length")
        else:
            content = base64.b64encode(secrets.token_bytes(size))

        pending[path] = (content, 0o600)

    with tempfile.TemporaryDirectory(prefix="homeharbor-sandbox-init-") as scratch:
        temp = Path(scratch)
        if has_relay:
            verify_pair(relay_cert, relay_key, ca, ["relay"])
        else:
            require_commands("openssl")
            staged_ca, staged_key = issue_authority(temp, "HomeHarbor Sandbox CA")
            staged_cert, staged_relay_key = issue(temp, "relay", staged_ca, staged_key, ["relay"])
            for destination, source, mode in (
                (ca, staged_ca, 0o644),
                (ca_key, staged_key, 0o600),
                (relay_cert, staged_cert, 0o644),
                (relay_key, staged_relay_key, 0o600),
            ):
                pending[destination] = (source.read_bytes(), mode)

            ca = staged_ca
            ca_key = staged_key

        names = [HOST_CONTROL, HOST_RELAY, GATEWAY_CONTROL, GATEWAY_RELAY]
        if has_front:
            verify_pair(front_cert, front_key, ca, names)
        else:
            staged_cert, staged_key = issue(temp, "frontend", ca, ca_key, names)
            pending[front_cert] = (staged_cert.read_bytes(), 0o644)
            pending[front_key] = (staged_key.read_bytes(), 0o600)

        if has_site:
            if same_authority(site_ca, ca):
                raise ValueError("private site must use a separate authority from control")

            verify_pair(site_ca, site_ca_key, site_ca, [])
            verify_pair(site_cert, site_key, site_ca, ["site.sandbox.home.arpa"], exact_names=True)
        else:
            # A separate fixture authority preserves existing control trust and
            # avoids propagating legacy control-CA strict-verifier limitations.
            site_staging = temp / "site-authority"
            site_staging.mkdir(mode=0o700)
            staged_ca, staged_ca_key = issue_authority(site_staging, "HomeHarbor Private Site CA")
            staged_cert, staged_key = issue(
                temp, "site", staged_ca, staged_ca_key, ["site.sandbox.home.arpa"]
            )
            pending[site_ca] = (staged_ca.read_bytes(), 0o644)
            pending[site_ca_key] = (staged_ca_key.read_bytes(), 0o600)
            pending[site_cert] = (staged_cert.read_bytes(), 0o644)
            pending[site_key] = (staged_key.read_bytes(), 0o600)

        if has_root:
            if mounted_root.read_bytes() != root_public.read_bytes():
                raise ValueError("sandbox mounted public root differs from companion root")
        else:
            require_commands("go")
            phrase = base64.b64encode(secrets.token_bytes(32))
            temp_phrase, temp_key = temp / "phrase", temp / "root-key.age"
            temp_phrase.write_bytes(phrase)
            public = quiet_run(
                "go",
                "run",
                "./cmd/admin",
                "init-root",
                "--key",
                str(temp_key),
                "--passphrase-file",
                str(temp_phrase),
            )
            if not public.strip() or not temp_key.is_file() or not temp_key.read_bytes():
                raise ValueError("sandbox companion root generation was incomplete")

            for destination, content, mode in (
                (root_key, temp_key.read_bytes(), 0o600),
                (root_public, public, 0o644),
                (mounted_root, public, 0o644),
                (passphrase, phrase, 0o600),
            ):
                pending[destination] = (content, mode)

    manifest = SANDBOX / "initial-snapshot.toml"
    check_destination(manifest)
    pending[manifest] = (
        resolve_manifest(
            manifest.read_bytes() if manifest.exists() else None,
            selected,
            gateway_public_identity(),
        ),
        0o600,
    )
    for path in pending:
        check_destination(path)

    for path, (content, mode) in pending.items():
        atomic_write(path, content, mode)

    print(f"Sandbox trust and config ready: {endpoint_audience('host', https_port).control}")


if __name__ == "__main__":
    raise SystemExit(cli(initialize))
