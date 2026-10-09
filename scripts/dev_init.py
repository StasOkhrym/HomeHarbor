"""Initialize local configs, companion keys and Traefik TLS without rotating trust."""

import base64
import os
import re
import secrets
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import tomlkit
from tooling import ROOT, atomic_write, cli, port, quiet_run, require_commands

SECRET_BYTES = {
    "postgres_password": 32,
    "redis_password": 32,
    "relay_ticket_key": 32,
    "session_signing_key": 48,
    "ceremony_encryption_key": 24,
}


def local_domain(value):
    labels = value.split(".")
    if (
        len(value) > 253
        or len(labels) < 2
        or labels[-1] != "localhost"
        or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) for s in labels)
    ):
        raise ValueError("Local domains must be valid lowercase *.localhost names")

    return value


def config(name):
    path = ROOT / f".local/{name}.toml"
    return tomlkit.parse(
        path.read_text() if path.exists() else (ROOT / f"config/{name}.example.toml").read_text()
    )


def defaults(document, values):
    for key, value in values.items():
        if key not in document:
            document[key] = value
        elif isinstance(value, dict):
            defaults(document[key], value)


def managed_url(value, hostname, examples, scheme, suffix="", https_port=8443):
    if urlsplit(value).hostname in {hostname, *examples}:
        return f"{scheme}://{hostname}:{https_port}{suffix}"

    return value


def configs(control_name, relay_name, https_port):
    control, relay, admin = config("control"), config("relay"), config("admin")
    defaults(control, tomlkit.parse((ROOT / "config/control.example.toml").read_text()).unwrap())
    defaults(relay, tomlkit.parse((ROOT / "config/relay.example.toml").read_text()).unwrap())
    control["server"]["public_url"] = managed_url(
        control["server"]["public_url"],
        control_name,
        {"tunnel.example.com"},
        "https",
        https_port=https_port,
    )
    control["auth"]["rp_origin"] = managed_url(
        control["auth"]["rp_origin"],
        control_name,
        {"tunnel.example.com"},
        "https",
        https_port=https_port,
    )
    if control["auth"]["rp_id"] in {"tunnel.example.com", control_name}:
        control["auth"]["rp_id"] = control_name
    control["relay"]["public_url"] = managed_url(
        control["relay"]["public_url"],
        relay_name,
        {"relay.example.com"},
        "wss",
        "/relay/udp/v2",
        https_port,
    )
    if urlsplit(control["database"]["url"]).hostname == "postgres":
        control["database"]["url"] = control["database"]["url"].replace("@postgres:", "@db:")
    control["security"]["root_public_key_file"] = "/run/secrets/root_public_key"
    if relay["server"]["udp_advertise_host"] == "relay.example.com":
        relay["server"]["udp_advertise_host"] = relay_name
    origin = f"https://{control_name}:{https_port}"
    admin.update(
        endpoint=origin,
        base_url=origin + "/invite",
        root_key_file=".local/root-key.age",
        passphrase_file=".local/root-passphrase",
        snapshot_manifest_file=".local/initial-snapshot.toml",
        invite_attempts_file=".local/invite-attempts.json",
    )
    return {
        ROOT / f".local/{name}.toml": (tomlkit.dumps(doc).encode(), 0o600)
        for name, doc in (("control", control), ("relay", relay), ("admin", admin))
    }


def complete(paths, label):
    present = [p.exists() for p in paths]
    if any(present) and not all(present):
        raise ValueError(f"{label} incomplete; restore the complete existing set")
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"{label}: symlink is not supported: {path.name}")
        if path.exists() and not path.read_bytes():
            raise ValueError(f"{label}: {path.name} is empty; restore it")
    return all(present)


def verify_pair(cert, key, ca, names):
    quiet_run("openssl", "verify", "-CAfile", str(ca), str(cert))
    cert_public = quiet_run("openssl", "x509", "-in", str(cert), "-pubkey", "-noout")
    key_public = quiet_run("openssl", "pkey", "-in", str(key), "-pubout")
    if cert_public != key_public:
        raise ValueError(f"TLS certificate/key mismatch: {cert.name}; restore the matching pair")
    description = quiet_run("openssl", "x509", "-in", str(cert), "-noout", "-text").decode()
    # LibreSSL on macOS lacks verify_hostname. Local certificates use exact SANs.
    extension = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*([^\n]+)", description)
    sans = set(re.findall(r"DNS:([^,\s]+)", extension[1])) if extension else set()
    if not set(names).issubset(sans):
        raise ValueError(
            f"TLS domains do not match {cert.name}; restore its matching configuration"
        )


def issue(directory, prefix, ca, ca_key, names):
    key, cert, csr, ext = [directory / f"{prefix}.{part}" for part in ("key", "cert", "csr", "ext")]
    quiet_run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-subj",
        "/CN=" + names[0],
        "-keyout",
        str(key),
        "-out",
        str(csr),
    )
    ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName="
        + ",".join("DNS:" + name for name in names)
        + "\n"
    )
    quiet_run(
        "openssl",
        "x509",
        "-req",
        "-days",
        "365",
        "-sha256",
        "-in",
        str(csr),
        "-CA",
        str(ca),
        "-CAkey",
        str(ca_key),
        "-set_serial",
        "0x" + secrets.token_hex(16),
        "-extfile",
        str(ext),
        "-out",
        str(cert),
    )
    verify_pair(cert, key, ca, names)
    return cert, key


def initialize():
    require_commands("openssl")
    control_name = local_domain(os.environ.get("CONTROL_DOMAIN", "control.localhost"))
    relay_name = local_domain(os.environ.get("RELAY_DOMAIN", "relay.localhost"))
    if control_name == relay_name:
        raise ValueError("CONTROL_DOMAIN and RELAY_DOMAIN must differ")
    https_port = port(os.environ.get("DEV_HTTPS_PORT", "8443"), "DEV_HTTPS_PORT")
    http_port = port(
        os.environ.get("PROXY_HTTP_PORT", os.environ.get("DEV_HTTP_PORT", "8088")),
        "PROXY_HTTP_PORT",
    )
    if http_port == https_port:
        raise ValueError("HTTP and HTTPS ports must differ")
    pending = configs(control_name, relay_name, https_port)  # Parse before any writes.
    local, secret_dir = ROOT / ".local", ROOT / "secrets"
    ca, cert, key = [secret_dir / f"relay_tls_{part}" for part in ("ca", "cert", "key")]
    ca_key = local / "relay-ca-key.pem"
    has_relay = complete([ca, cert, key], "Relay TLS")
    frontend_cert, frontend_key = [secret_dir / f"frontend_tls_{part}" for part in ("cert", "key")]
    has_frontend = complete([frontend_cert, frontend_key], "Frontend TLS")
    root_key, root_public = local / "root-key.age", local / "root-public.key"
    has_root = complete([root_key, root_public], "Local companion root key")
    passphrase = local / "root-passphrase"
    if has_root and (not passphrase.exists() or not passphrase.read_bytes()):
        raise ValueError("Local companion root passphrase missing; restore .local/root-passphrase")
    mounted_public = secret_dir / "root_public_key"
    if mounted_public.exists() and (
        not has_root or mounted_public.read_bytes() != root_public.read_bytes()
    ):
        raise ValueError(
            "secrets/root_public_key differs from .local/root-public.key; restore matching trust"
        )
    if not has_root:
        require_commands("go")
    for name, size in SECRET_BYTES.items():
        path = secret_dir / name
        length = ((size + 2) // 3) * 4
        if path.exists():
            if len(path.read_bytes()) != length:
                raise ValueError(f"secrets/{name} must contain exactly {length} bytes; restore it")
            pending[path] = (path.read_bytes(), 0o600)
        else:
            pending[path] = (base64.b64encode(secrets.token_bytes(size)), 0o600)
    # Stage all generated material privately; a command failure publishes nothing.
    with tempfile.TemporaryDirectory(prefix="homeharbor-init-") as scratch:
        temp = Path(scratch)
        if has_relay:
            verify_pair(cert, key, ca, ["relay"])
        else:
            if ca_key.exists() or has_frontend:
                raise ValueError(
                    "Existing local CA/frontend TLS without relay certificates; restore TLS"
                )
            staged_ca, staged_ca_key = temp / "ca", temp / "ca-key"
            quiet_run(
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-sha256",
                "-subj",
                "/CN=HomeHarbor Local Relay CA",
                "-keyout",
                str(staged_ca_key),
                "-out",
                str(staged_ca),
            )
            staged_cert, staged_key = issue(
                temp, "relay", staged_ca, staged_ca_key, ["relay", "localhost"]
            )
            for dest, source, mode in (
                (ca, staged_ca, 0o644),
                (ca_key, staged_ca_key, 0o600),
                (cert, staged_cert, 0o644),
                (key, staged_key, 0o600),
            ):
                pending[dest] = (source.read_bytes(), mode)
            ca, ca_key = staged_ca, staged_ca_key
        if has_frontend:
            verify_pair(frontend_cert, frontend_key, ca, [control_name, relay_name])
        else:
            if not ca_key.is_file():
                raise ValueError("Local CA private key missing; cannot issue frontend TLS")
            # Validate that this key belongs to the existing CA before signing.
            if quiet_run("openssl", "x509", "-in", str(ca), "-pubkey", "-noout") != quiet_run(
                "openssl", "pkey", "-in", str(ca_key), "-pubout"
            ):
                raise ValueError("Local CA certificate/private key mismatch; restore matching TLS")
            new_cert, new_key = issue(temp, "frontend", ca, ca_key, [control_name, relay_name])
            pending[frontend_cert] = (new_cert.read_bytes(), 0o644)
            pending[frontend_key] = (new_key.read_bytes(), 0o600)
        if not has_root:
            phrase = (
                passphrase.read_bytes()
                if passphrase.exists()
                else base64.b64encode(secrets.token_bytes(32))
            )
            if not phrase:
                raise ValueError("Local root passphrase is empty")
            temp_phrase, temp_key = temp / "passphrase", temp / "root-key.age"
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
                raise ValueError("Companion root generation produced incomplete keys")
            pending[root_key] = (temp_key.read_bytes(), 0o600)
            pending[root_public] = (public, 0o644)
            pending[passphrase] = (phrase, 0o600)
        else:
            public = root_public.read_bytes()
        if not mounted_public.exists():
            pending[mounted_public] = (public, 0o644)
    routes = tomlkit.parse((ROOT / "deploy/traefik/routes.toml").read_text())
    for name, domain in (("control", control_name), ("relay", relay_name)):
        router = routes["http"]["routers"][name]
        router["rule"] = f"Host(`{domain}`)"
    routes["tls"] = {
        "certificates": [
            {
                "certFile": "/run/secrets/frontend_tls_cert",
                "keyFile": "/run/secrets/frontend_tls_key",
            }
        ]
    }
    pending[local / "traefik/dynamic/routes.toml"] = (tomlkit.dumps(routes).encode(), 0o644)
    snapshot = local / "initial-snapshot.toml"
    if not snapshot.exists():
        pending[snapshot] = ((ROOT / "config/initial-snapshot.example.toml").read_bytes(), 0o600)
    # Reusing trust does not mean reusing unsafe filesystem permissions. Stage
    # existing private material too, after validation, without changing bytes.
    for path in (root_key, passphrase, local / "relay-ca-key.pem", key, frontend_key):
        if path.exists() and path not in pending:
            pending[path] = (path.read_bytes(), 0o600)
    # Reject all symlink destinations before the first publication.
    for path in pending:
        if path.is_symlink() or any(
            parent.is_symlink() for parent in path.parents if parent != ROOT
        ):
            raise ValueError(f"Refusing to write through symlink: {path}")
    for path, (content, mode) in pending.items():
        atomic_write(path, content, mode)
    (local / "traefik/state").mkdir(parents=True, exist_ok=True)
    print(f"Local configuration ready: https://{control_name}:{https_port}")


if __name__ == "__main__":
    raise SystemExit(cli(initialize))
