"""Prepare the separate optional iPhone LAN sandbox; no native Mac helper effects."""

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
from dataclasses import asdict

from sandbox_identity import unique_fields
from sandbox_ios_config import (
    DIRECTORY,
    PROJECT,
    LANEndpoints,
    configuration_documents,
    render_compose,
)
from sandbox_ios_handoff import public_handoff
from sandbox_ios_material import material_documents
from sandbox_ownership import SandboxOwnership, quiet_command
from sandbox_preflight import (
    PROFILES,
    load_profile,
    parse_route_destination,
    probe_kernel,
    reject_overlaps,
    select_profile,
)
from tooling import ROOT, atomic_write, cli


def available_ports(endpoints):
    """Hold all requested bindings together during the read-only availability probe."""

    with contextlib.ExitStack() as stack:
        for address, port, kind in [
            (endpoints.address, endpoints.control_port, socket.SOCK_STREAM),
            (endpoints.address, endpoints.relay_port, socket.SOCK_STREAM),
            ("127.0.0.1", endpoints.admin_port, socket.SOCK_STREAM),
            *(
                (endpoints.address, port, socket.SOCK_DGRAM)
                for port in range(endpoints.udp_min, endpoints.udp_max + 1)
            ),
        ]:
            channel = stack.enter_context(socket.socket(socket.AF_INET, kind))

            try:
                channel.bind((address, port))
            except OSError:
                raise ValueError(
                    "requested iPhone sandbox TCP/UDP binding is unavailable"
                ) from None


class IOSWorkflow(SandboxOwnership):
    def __init__(self, root=ROOT, *, run=quiet_command, uid=None):
        super().__init__(root, project=PROJECT, directory=DIRECTORY, run=run, uid=uid)

    def require_local_docker(self):
        endpoint = os.environ.get("DOCKER_HOST")
        if not endpoint:
            try:
                endpoint = json.loads(
                    self.command(
                        [
                            "docker",
                            "context",
                            "inspect",
                            "--format",
                            "{{json .Endpoints.docker.Host}}",
                        ],
                        timeout=30,
                    )
                )
            except ValueError:
                raise ValueError("cannot determine the local Docker endpoint") from None

        if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
            raise ValueError("iPhone sandbox requires a local Docker Unix socket")

    def existing_networks(self):
        routes = self.command(["netstat", "-rn", "-f", "inet"], timeout=30)
        existing = []
        for line in routes.splitlines():
            fields = line.split()
            network = parse_route_destination(fields[0]) if fields else None
            if network is not None:
                existing.append(network)

        ids = self.command(["docker", "network", "ls", "--quiet"], timeout=30).split()
        if ids:
            raw = self.command(["docker", "network", "inspect", *ids], timeout=30)

            try:
                items = json.loads(raw, object_pairs_hook=unique_fields)
                if not isinstance(items, list) or len(items) != len(ids):
                    raise ValueError

                for item in items:
                    for config in item.get("IPAM", {}).get("Config") or []:
                        if config.get("Subnet"):
                            existing.append(ipaddress.ip_network(config["Subnet"], strict=False))
            except (ValueError, AttributeError, TypeError):
                raise ValueError("cannot inspect all Docker network pools") from None

        return existing

    def require_assigned(self, endpoints):
        interfaces = self.command(["/sbin/ifconfig", "-a"], timeout=30)
        assigned = re.findall(r"^\s+inet ([0-9.]+)\s", interfaces, re.MULTILINE)
        if endpoints.address not in assigned:
            raise ValueError("selected LAN IPv4 is not assigned to this Mac")

    def destination(self, path):
        self.check_path(path)
        if path.exists() and not path.is_file():
            raise ValueError("generated iPhone sandbox destination must be a regular file")

    def prepare(self, address):
        endpoints = LANEndpoints(address)
        self.require_local_docker()

        with self.lock():
            self.create_owner()
            resources = self.inventory()
            if resources["container"] or resources["network"]:
                raise ValueError("stop the iPhone sandbox before preparing its state")

            self.require_assigned(endpoints)
            existing = self.existing_networks()
            marker = self.sandbox / "lan.json"
            self.destination(marker)
            metadata = None
            if marker.exists():
                try:
                    metadata = json.loads(marker.read_bytes(), object_pairs_hook=unique_fields)
                    profile = next(p for p in PROFILES if p.environment() == metadata["network"])
                    expected = {
                        "version": 1,
                        "endpoints": asdict(endpoints),
                        "network": profile.environment(),
                    }
                    if metadata != expected:
                        raise ValueError
                except (ValueError, TypeError, KeyError, StopIteration):
                    raise ValueError(
                        "iPhone endpoints/profile changed or malformed; preserve existing state for explicit review"
                    ) from None

                reject_overlaps(existing, profile.pools)
            else:
                if any(
                    p.name not in {"workflow.lock", "workflow-owner.json"}
                    for p in self.sandbox.iterdir()
                ):
                    raise ValueError(
                        "incomplete iPhone preparation; restore or explicitly review existing state"
                    )

                profile = select_profile(existing)

            configs = configuration_documents(self.root, profile, endpoints)
            candidates = {path: (raw, 0o600) for path, raw in configs.items()}
            candidates[self.sandbox / "compose.yaml"] = (
                render_compose(self.root, endpoints),
                0o600,
            )
            env = "".join(
                f"{key}={value}\n" for key, value in profile.environment().items()
            ).encode()
            candidates[self.sandbox / "network.env"] = (env, 0o600)
            for folder in [self.sandbox / "secrets", self.sandbox / "public"]:
                self.check_path(folder)
                if folder.exists() and not folder.is_dir():
                    raise ValueError("iPhone private state parent must be a directory")

            handoff_names = [
                "homeharbor-ios.mobileconfig",
                "control-ca.pem",
                "site-ca.pem",
                "fingerprints.txt",
            ]
            for path in [*candidates, *(self.sandbox / "public" / name for name in handoff_names)]:
                self.destination(path)

            materials = material_documents(self, endpoints)
            candidates.update(materials)
            public = public_handoff(
                materials[self.sandbox / "secrets/relay_tls_ca"][0],
                materials[self.sandbox / "secrets/site_tls_ca"][0],
            )
            candidates.update(
                {self.sandbox / "public" / name: (data, 0o644) for name, data in public.items()}
            )
            for path in candidates:
                self.destination(path)

            for folder in [self.sandbox, self.sandbox / "secrets", self.sandbox / "public"]:
                folder.mkdir(mode=0o700, exist_ok=True)
                folder.chmod(0o700)

            for path, (raw, mode) in candidates.items():
                atomic_write(path, raw, mode)

            metadata = {
                "version": 1,
                "endpoints": asdict(endpoints),
                "network": profile.environment(),
            }
            atomic_write(marker, (json.dumps(metadata, sort_keys=True) + "\n").encode())

        return endpoints

    def prepared(self):
        self.require_owner()
        marker = self.sandbox / "lan.json"
        self.destination(marker)

        try:
            metadata = json.loads(marker.read_bytes(), object_pairs_hook=unique_fields)
            endpoints = LANEndpoints(**metadata["endpoints"])
            profile = next(p for p in PROFILES if p.environment() == metadata["network"])
            if metadata != {
                "version": 1,
                "endpoints": asdict(endpoints),
                "network": profile.environment(),
            }:
                raise ValueError
        except (OSError, ValueError, TypeError, KeyError, StopIteration):
            raise ValueError("iPhone preparation metadata is missing or malformed") from None

        for name in ["compose.yaml", "network.env"]:
            self.destination(self.sandbox / name)

        if not (self.sandbox / "network.env").is_file():
            raise ValueError("iPhone network profile is missing")

        for path in self.sandbox.rglob("*"):
            self.check_path(path)

        if load_profile(self.sandbox / "network.env") != profile.environment():
            raise ValueError("iPhone network profile differs from prepared state")
        if (self.sandbox / "compose.yaml").read_bytes() != render_compose(self.root, endpoints):
            raise ValueError(
                "iPhone Compose differs from generated state; explicit review required"
            )

        return endpoints

    def environment(self):
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COMPOSE_", "SANDBOX_", "RUNTIME_", "HOMEHARBOR_"))
            and key not in {"CONTROL_CONFIG", "RELAY_CONFIG", "DOCKER_DEFAULT_PLATFORM"}
        }
        env.update(
            SANDBOX_WORKSPACE=str(self.root),
            SANDBOX_OWNER_UID=str(self.uid),
            RUNTIME_UID=str(self.uid),
            RUNTIME_GID=str(os.getgid()),
        )
        return env

    def compose(self, *args, timeout=180):
        self.prepared()
        return self.command(
            [
                "docker",
                "compose",
                "--project-name",
                PROJECT,
                "--project-directory",
                str(self.root / "deploy"),
                "--env-file",
                str(self.sandbox / "network.env"),
                "--file",
                str(self.sandbox / "compose.yaml"),
                "--profile",
                "native-client",
                *args,
            ],
            env=self.environment(),
            timeout=timeout,
        )

    def up(self, address):
        if sys.platform != "darwin":
            raise ValueError("the optional iPhone LAN sandbox requires macOS")

        endpoints = self.prepare(address)

        with self.lock():
            self.require_local_docker()
            resources = self.inventory()
            if resources["container"] or resources["network"]:
                raise ValueError("existing iPhone sandbox resources; stop before starting")

            self.require_assigned(endpoints)
            available_ports(endpoints)
            tag = hashlib.sha256(f"{self.root}\0{self.uid}".encode()).hexdigest()[:16]
            image = f"homeharbor-ios-sandbox-gateway-probe:{tag}"
            self.command(
                [
                    "docker",
                    "build",
                    "--target",
                    "probe",
                    "--tag",
                    image,
                    "--file",
                    str(self.root / "deploy/sandbox/Dockerfile.gateway"),
                    str(self.root),
                ],
                timeout=600,
            )
            probe_kernel(image)
            self.compose("config", "--quiet")
            self.compose("build", timeout=900)
            self.compose(
                "up",
                "--detach",
                "--wait",
                "--wait-timeout",
                "180",
                "db",
                "redis",
                "migrate",
                "control",
                "relay",
                "proxy",
                "dns",
                "site",
                timeout=240,
            )

        return endpoints

    def down(self):
        self.require_local_docker()
        self.require_owner()

        with self.lock():
            self.inventory()
            self.compose("down", "--timeout", "140", timeout=180)

    def status(self):
        self.require_local_docker()
        self.require_owner()

        with self.lock():
            endpoints = self.prepared()
            resources = self.inventory()

            return {
                "control": endpoints.control,
                "relay": endpoints.relay,
                "admin": endpoints.admin,
                "containers": len(resources["container"]),
                "running": sum(
                    bool(item.get("State", {}).get("Running")) for item in resources["container"]
                ),
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "up", "down", "status"])
    parser.add_argument("--lan-ip")
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise ValueError("the optional iPhone LAN sandbox requires macOS")
    flow = IOSWorkflow()
    if args.action in {"prepare", "up"}:
        if args.lan_ip is None:
            parser.error("provide --lan-ip with the explicit Mac LAN IPv4")
        endpoints = flow.prepare(args.lan_ip) if args.action == "prepare" else flow.up(args.lan_ip)
        verb = (
            "prepared; services are stopped"
            if args.action == "prepare"
            else "infrastructure started; gateway enrollment/signing still required"
        )
        print(f"iPhone sandbox {verb}")
        print(f"Control: {endpoints.control}; admin: {endpoints.admin}")
        print("Public certificate handoff: .sandbox-ios/public (not installed or trusted)")
    elif args.action == "down":
        flow.down()
        print("Owned iPhone sandbox stopped; identities and volumes preserved")
    else:
        print(json.dumps(flow.status(), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(cli(main))
