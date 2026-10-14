"""Read-only macOS/Docker checks for the opt-in native sandbox."""

import argparse
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from tooling import ROOT, atomic_write, cli, require_commands

BACKEND = ipaddress.ip_network("172.30.60.0/24")
UNDERLAY = ipaddress.ip_network("172.28.40.0/24")
PRIVATE = ipaddress.ip_network("172.29.50.0/24")
OVERLAY = ipaddress.ip_network("10.200.0.0/24")
POOLS = (BACKEND, UNDERLAY, PRIVATE, OVERLAY)
GATEWAY_PROBE_IMAGE = "homeharbor-sandbox-gateway-probe"
NETWORK_FILE = ROOT / ".sandbox/network.env"


@dataclass(frozen=True)
class PoolProfile:
    backend: ipaddress.IPv4Network
    underlay: ipaddress.IPv4Network
    private: ipaddress.IPv4Network
    overlay: ipaddress.IPv4Network

    @property
    def pools(self):
        return (self.backend, self.underlay, self.private, self.overlay)

    def environment(self):
        return {
            "SANDBOX_BACKEND_SUBNET": str(self.backend),
            "SANDBOX_UNDERLAY_SUBNET": str(self.underlay),
            "SANDBOX_PRIVATE_SUBNET": str(self.private),
            "SANDBOX_OVERLAY_SUBNET": str(self.overlay),
            "SANDBOX_PROXY_BACKEND_IP": str(self.backend.network_address + 10),
            "SANDBOX_PROXY_UNDERLAY_IP": str(self.underlay.network_address + 10),
            "SANDBOX_UNDERLAY_IP": str(self.underlay.network_address + 2),
            "SANDBOX_RELAY_UNDERLAY_IP": str(self.underlay.network_address + 20),
            "SANDBOX_PRIVATE_GATEWAY_IP": str(self.private.network_address + 2),
            "SANDBOX_DNS_IP": str(self.private.network_address + 53),
            "SANDBOX_SITE_IP": str(self.private.network_address + 80),
            "SANDBOX_GATEWAY_OVERLAY_IP": str(self.overlay.network_address + 2),
        }


PROFILES = (
    PoolProfile(BACKEND, UNDERLAY, PRIVATE, OVERLAY),
    PoolProfile(
        ipaddress.ip_network("10.242.60.0/24"),
        ipaddress.ip_network("10.240.40.0/24"),
        ipaddress.ip_network("10.241.50.0/24"),
        ipaddress.ip_network("10.243.0.0/24"),
    ),
    PoolProfile(
        ipaddress.ip_network("10.252.60.0/24"),
        ipaddress.ip_network("10.250.40.0/24"),
        ipaddress.ip_network("10.251.50.0/24"),
        ipaddress.ip_network("10.253.0.0/24"),
    ),
)


def reject_overlaps(existing, pools=POOLS):
    for index, left in enumerate(pools):
        if left.prefixlen == 0 or any(left.overlaps(other) for other in pools[index + 1 :]):
            raise ValueError(f"sandbox pool is invalid or overlaps another pool: {left}")

        for network in existing:
            if left.overlaps(network):
                raise ValueError(f"sandbox pool {left} overlaps an existing network {network}")


def select_profile(existing):
    for profile in PROFILES:
        try:
            reject_overlaps(existing, profile.pools)
        except ValueError:
            continue

        return profile

    raise ValueError("no collision-free sandbox pool profile; choose explicit safe pools")


def save_profile(profile: PoolProfile, path: Path = NETWORK_FILE):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("sandbox network state must not use symlinks")
    if profile not in PROFILES:
        raise ValueError("sandbox network profile must be one of the vetted local profiles")

    values = profile.environment()
    content = "".join(f"{key}={value}\n" for key, value in values.items()).encode()
    atomic_write(path, content, 0o600)


def load_profile(path: Path = NETWORK_FILE):
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("sandbox network state must not use symlinks")
    if not path.exists():
        return PROFILES[0].environment()

    values = {}
    for line in path.read_text().splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in PROFILES[0].environment() or key in values:
            raise ValueError("sandbox network state is malformed")

        values[key] = value

    if set(values) != set(PROFILES[0].environment()):
        raise ValueError("sandbox network state is incomplete")

    selected = PoolProfile(
        *(
            ipaddress.ip_network(values[key])
            for key in (
                "SANDBOX_BACKEND_SUBNET",
                "SANDBOX_UNDERLAY_SUBNET",
                "SANDBOX_PRIVATE_SUBNET",
                "SANDBOX_OVERLAY_SUBNET",
            )
        )
    )
    if selected not in PROFILES or selected.environment() != values:
        raise ValueError("sandbox network state contains inconsistent addresses")

    return values


def parse_route_destination(raw):
    if raw in {"default", "Destination"}:
        return None

    try:
        address, separator, bits = raw.partition("/")
        pieces = address.split(".")
        if len(pieces) > 4 or not all(piece.isdecimal() for piece in pieces):
            return None

        expanded = ".".join([*pieces, *(["0"] * (4 - len(pieces)))])
        prefix = int(bits) if separator else len(pieces) * 8
        if len(pieces) == 4 and not separator:
            prefix = 32

        network = ipaddress.ip_network(f"{expanded}/{prefix}", strict=False)

        return None if network.is_multicast or network.is_loopback else network
    except ValueError:
        return None


def host_routes():
    result = subprocess.run(
        ["netstat", "-rn", "-f", "inet"], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise ValueError("cannot inspect macOS IPv4 routes")

    networks = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields:
            network = parse_route_destination(fields[0])
            if network is not None:
                networks.append(network)

    return networks


def docker_networks():
    listed = subprocess.run(
        ["docker", "network", "ls", "-q"], capture_output=True, text=True, check=False
    )
    if listed.returncode:
        raise ValueError("cannot list Docker networks")

    ids = listed.stdout.split()
    if not ids:
        return []

    inspected = subprocess.run(
        ["docker", "network", "inspect", *ids], capture_output=True, text=True, check=False
    )
    if inspected.returncode:
        raise ValueError("cannot inspect Docker network pools")

    networks = []
    for item in json.loads(inspected.stdout):
        for entry in item.get("IPAM", {}).get("Config") or []:
            if entry.get("Subnet"):
                networks.append(ipaddress.ip_network(entry["Subnet"], strict=False))

    return networks


def project_containers():
    result = subprocess.run(
        [
            "docker",
            "ps",
            "--all",
            "--quiet",
            "--filter",
            "label=com.docker.compose.project=homeharbor-sandbox",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("cannot inspect existing sandbox containers")

    return bool(result.stdout.strip())


def probe_kernel(image=GATEWAY_PROBE_IMAGE):
    # This disposable namespace is unrelated to the sandbox Compose project.
    # It proves the Docker VM kernel supports the operations the gateway needs.
    probe = (
        "set -eu; "
        "ip link add wg-hhprobe type wireguard; "
        "ip link delete wg-hhprobe; "
        "nft add table inet hh_probe; "
        "nft add chain inet hh_probe forward '{ type filter hook forward priority 0; policy accept; }'; "
        "nft delete table inet hh_probe; "
        "test "
        '"$(cat /proc/sys/net/ipv4/ip_forward)" = 1'
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-add",
            "NET_ADMIN",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--entrypoint",
            "sh",
            image,
            "-ec",
            probe,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("Docker VM lacks WireGuard/nft/forwarding capability or probe image")


def preflight(*, check_only=False, probe_image=GATEWAY_PROBE_IMAGE):
    require_commands("docker", "netstat")
    if project_containers():
        raise ValueError("stop and remove the existing sandbox project before preflight")

    existing = [*host_routes(), *docker_networks()]
    if NETWORK_FILE.exists():
        values = load_profile()
        selected = next(profile for profile in PROFILES if profile.environment() == values)
        reject_overlaps(existing, selected.pools)
    else:
        selected = select_profile(existing)

    if check_only:
        return selected

    probe_kernel(probe_image)
    save_profile(selected)
    print("Sandbox pools selected: " + ", ".join(map(str, selected.pools)))
    print("Docker VM WireGuard/nft/forwarding capability passed")
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-pools", action="store_true")
    parser.add_argument("--probe-image", default=GATEWAY_PROBE_IMAGE)
    args = parser.parse_args()
    if args.probe_image != GATEWAY_PROBE_IMAGE and not re.fullmatch(
        r"homeharbor-sandbox-gateway-probe:[0-9a-f]{16}", args.probe_image
    ):
        raise ValueError("sandbox probe image must use its checkout-scoped tag")

    preflight(check_only=args.check_pools, probe_image=args.probe_image)


if __name__ == "__main__":
    raise SystemExit(cli(main))
