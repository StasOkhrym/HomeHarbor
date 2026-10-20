"""Pure configuration for the separate, opt-in physical iPhone LAN flow."""

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import tomlkit
import yaml
from sandbox_preflight import PROFILES, PoolProfile

PROJECT = "homeharbor-ios-sandbox"
DIRECTORY = ".sandbox-ios"
NETWORK_ID = "ios-sandbox-network"
PROFILE_ID = "ios-sandbox"
ADMIN_HOST = "ios-admin.localhost"
CONTROL_HOST = "control.ios-sandbox"
RELAY_HOST = "relay.ios-sandbox"
MOBILE_API_PATHS = (
    r"^/(?:readyz|api/v1/(?:"
    r"invites/(?:proof|[A-Za-z0-9_-]{1,128}(?:/(?:challenge|claim))?)|"
    r"devices/(?:credentials/(?:challenge|recovery|rotate)|self/metadata)|"
    r"coordination(?:/snapshots)?|relay-sessions))$"
)
PRIVATE_LANS = tuple(
    ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True)
class LANEndpoints:
    address: str
    control_port: int = 19443
    relay_port: int = 19444
    admin_port: int = 19445
    udp_min: int = 52120
    udp_max: int = 52135

    def __post_init__(self):
        try:
            address = ipaddress.IPv4Address(self.address)
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("select an explicit RFC1918 LAN IPv4 address") from None

        if str(address) != self.address or not any(address in network for network in PRIVATE_LANS):
            raise ValueError("select an explicit RFC1918 LAN IPv4 address")

        ports = (self.control_port, self.relay_port, self.admin_port, self.udp_min, self.udp_max)
        if any(type(value) is not int or not 1024 <= value <= 65535 for value in ports):
            raise ValueError("iPhone sandbox requires unprivileged integer ports")
        if len(set(ports[:3])) != 3 or not 1 <= self.udp_max - self.udp_min + 1 <= 16:
            raise ValueError("choose distinct TCP ports and at most16 ordered UDP ports")

    @property
    def control(self):
        return f"https://{self.address}:{self.control_port}"

    @property
    def relay(self):
        return f"wss://{self.address}:{self.relay_port}/relay/udp"

    @property
    def admin(self):
        return f"https://{ADMIN_HOST}:{self.admin_port}"


def configuration_documents(root: Path, profile: PoolProfile, endpoints: LANEndpoints):
    """Read public templates only; return private-state candidates without writes."""
    if not root.is_absolute() or profile not in PROFILES:
        raise ValueError("iPhone sandbox needs an absolute workspace and vetted network profile")
    if any(ipaddress.ip_address(endpoints.address) in network for network in profile.pools):
        raise ValueError("LAN ingress overlaps the selected Docker or overlay network")
    state = root / DIRECTORY
    selected = profile.environment()

    def template(name):
        return tomlkit.parse((root / f"config/{name}.example.toml").read_text())

    control = template("control")
    control["server"]["public_url"] = endpoints.control
    control["auth"]["rp_id"] = ADMIN_HOST
    control["auth"]["rp_origin"] = endpoints.admin
    control["auth"]["allow_remote_setup"] = False
    control["relay"]["public_url"] = endpoints.relay
    control["networking"]["network_id"] = NETWORK_ID
    control["security"]["trusted_proxy_cidrs"] = [selected["SANDBOX_PROXY_BACKEND_IP"] + "/32"]

    relay = template("relay")
    relay["server"]["udp_listen_address"] = f":{endpoints.udp_min}"
    relay["server"]["udp_port_min"] = endpoints.udp_min
    relay["server"]["udp_port_max"] = endpoints.udp_max
    relay["server"]["udp_advertise_host"] = ""
    relay["server"]["udp_advertise_hosts"] = {
        endpoints.address: endpoints.address,
        RELAY_HOST: "relay",
    }

    gateway = template("agent")
    gateway["node"]["state_path"] = "/var/lib/homeharbor/gateway.json"
    gateway["node"]["control_url"] = f"https://{CONTROL_HOST}:8443"
    gateway["node"]["ca_file"] = "/run/secrets/relay_tls_ca"
    gateway["node"]["name"] = "iPhone sandbox gateway"
    gateway["relay"]["websocket_url"] = f"wss://{RELAY_HOST}:8443/relay/udp"
    gateway["relay"]["signed_peers"] = True
    gateway["relay"]["session_id"] = ""
    gateway["relay"]["destination_device_id"] = ""
    gateway["relay"]["wireguard_address"] = "127.0.0.1:51820"
    gateway["wireguard"]["interface"] = "wg0"
    gateway["wireguard"]["listen_port"] = 51820
    for key in ("peer_public_key", "overlay_address", "allowed_prefixes", "routes"):
        gateway["wireguard"][key] = ""
    gateway["coordination"]["url"] = f"wss://{CONTROL_HOST}:8443/api/v1/coordination"
    gateway["coordination"]["root_public_key_file"] = "/run/secrets/root_public_key"
    gateway["coordination"]["network_id"] = NETWORK_ID
    gateway["dns"]["enable_forwarding"] = False

    admin = template("admin")
    admin["endpoint"] = endpoints.admin
    admin["ca_file"] = str(state / "secrets/relay_tls_ca")
    admin["base_url"] = endpoints.control + "/invite"
    admin["network_id"] = NETWORK_ID
    admin["profile_id"] = PROFILE_ID
    admin["overlay_pool"] = selected["SANDBOX_OVERLAY_SUBNET"]
    for key, name in (
        ("root_key_file", "root-key.age"),
        ("passphrase_file", "root-passphrase"),
        ("snapshot_manifest_file", "initial-snapshot.toml"),
        ("invite_attempts_file", "invite-attempts.json"),
    ):
        admin[key] = str(state / name)

    proxy = {
        "entryPoints": {
            "websecure": {"address": ":8443"},
            "mobilecontrol": {"address": ":8444"},
            "mobilerelay": {"address": ":8445"},
        },
        "providers": {"file": {"directory": "/etc/traefik/dynamic", "watch": True}},
        "ping": {"entryPoint": "websecure"},
        "log": {"format": "json", "level": "INFO"},
    }
    routers = {}
    for name, hostname, entry, service in (
        ("admin", ADMIN_HOST, "websecure", "control"),
        ("control", CONTROL_HOST, "websecure", "control"),
        ("relay", RELAY_HOST, "websecure", "relay"),
        ("mobilecontrol", endpoints.address, "mobilecontrol", "control"),
        ("mobilerelay", endpoints.address, "mobilerelay", "relay"),
    ):
        routers[name] = {
            "rule": f"Host(`{hostname}`)",
            "entryPoints": [entry],
            "service": service,
            "tls": {},
        }
    routers["mobilecontrol"]["rule"] += f" && PathRegexp(`{MOBILE_API_PATHS}`)"
    routers["mobilerelay"]["rule"] += " && Path(`/relay/udp`)"
    routes = {
        "http": {
            "routers": routers,
            "services": {
                "control": {"loadBalancer": {"servers": [{"url": "http://control:8080"}]}},
                "relay": {
                    "loadBalancer": {
                        "serversTransport": "relay",
                        "servers": [{"url": "https://relay:8081"}],
                    }
                },
            },
            "serversTransports": {
                "relay": {"serverName": "relay", "rootCAs": ["/run/secrets/relay_tls_ca"]}
            },
        },
        "tls": {
            "certificates": [
                {
                    "certFile": "/run/secrets/frontend_tls_cert",
                    "keyFile": "/run/secrets/frontend_tls_key",
                }
            ]
        },
    }
    return {
        state / f"{name}.toml": tomlkit.dumps(document).encode()
        for name, document in (
            ("control", control),
            ("relay", relay),
            ("gateway", gateway),
            ("admin", admin),
            ("proxy", proxy),
            ("proxy-routes", routes),
        )
    }


def render_compose(root: Path, endpoints: LANEndpoints) -> bytes:
    """Reuse the public private-network fixture; replace all host/state bindings.

    This renders one complete Compose file before Compose performs inheritance.
    No override-file port-list merge can accidentally retain the Mac ingress.
    """

    state = root / DIRECTORY
    document = yaml.safe_load((root / "deploy/compose.sandbox.yaml").read_text())
    document["name"] = PROJECT
    for service in document["services"].values():
        if "extends" in service:
            service["extends"]["file"] = str(root / "deploy/compose.yaml")

    document["services"]["relay"]["ports"] = [
        f"{endpoints.address}:{endpoints.udp_min}-{endpoints.udp_max}:"
        f"{endpoints.udp_min}-{endpoints.udp_max}/udp"
    ]
    proxy = document["services"]["proxy"]
    proxy["ports"] = [
        f"{endpoints.address}:{endpoints.control_port}:8444",
        f"{endpoints.address}:{endpoints.relay_port}:8445",
        f"127.0.0.1:{endpoints.admin_port}:8443",
    ]
    proxy["networks"]["underlay"]["aliases"] = [CONTROL_HOST, RELAY_HOST]
    for key, filename in (
        ("control_config", "control.toml"),
        ("relay_config", "relay.toml"),
        ("gateway_config", "gateway.toml"),
        ("sandbox_proxy_config", "proxy.toml"),
        ("sandbox_proxy_routes", "proxy-routes.toml"),
    ):
        document["configs"][key]["file"] = str(state / filename)

    for key, secret in document["secrets"].items():
        secret["file"] = str(state / "secrets" / key)

    return yaml.safe_dump(document, sort_keys=False).encode()
