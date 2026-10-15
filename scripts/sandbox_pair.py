"""Public-only native pair documents; privilege/trust installation stays explicit."""

import base64
import binascii
import hashlib
import json
from pathlib import Path

import tomlkit
from sandbox_identity import (
    load_public_identity,
    read_public_file,
    unique_fields,
    validate_public_identity,
)
from sandbox_preflight import PROFILES


def pair_documents(
    sandbox: Path,
    selected: dict[str, str],
    gateway: dict[str, str],
    client: dict[str, str],
    root: str,
    uid: int,
    https_port: int = 8443,
    wireguard_port: int = 51830,
    bridge_port: int = 51831,
) -> dict[Path, tuple[bytes, int]]:
    gateway, client = validate_public_identity(gateway), validate_public_identity(client)
    if selected not in [profile.environment() for profile in PROFILES]:
        raise ValueError("native pair requires a vetted sandbox network profile")
    if type(uid) is not int or uid <= 0 or not sandbox.is_absolute():
        raise ValueError("native pair requires a non-root owner and absolute sandbox state")
    if (
        any(
            type(value) is not int or not 1024 <= value <= 65535
            for value in (https_port, wireguard_port, bridge_port)
        )
        or bridge_port == wireguard_port
    ):
        raise ValueError("native pair requires distinct unprivileged loopback ports")

    try:
        signing = base64.b64decode(root + "=", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValueError("native pair requires a canonical public signing root") from None

    if (
        len(signing) != 32
        or not any(signing)
        or base64.urlsafe_b64encode(signing).decode().rstrip("=") != root
    ):
        raise ValueError("native pair requires a canonical public signing root")
    if any(gateway[key] == client[key] for key in gateway) or root in (
        gateway["identity_public_key"],
        client["identity_public_key"],
    ):
        raise ValueError("gateway, client and signing root require independent identities")

    session = (
        "sandbox-"
        + hashlib.sha256(json.dumps([gateway, client], sort_keys=True).encode()).hexdigest()[:32]
    )
    runtime = {"operation_timeout": "30s", "cleanup_timeout": "5s"}
    native = {
        "node": {
            "state_path": str(sandbox / "client.json"),
            "control_url": f"https://control.localhost:{https_port}",
            "ca_file": str(sandbox / "secrets/relay_tls_ca"),
            "name": "sandbox-native-client",
        },
        "relay": {
            "websocket_url": f"wss://relay.localhost:{https_port}/relay/udp",
            "session_id": session,
            "destination_device_id": gateway["device_id"],
            "listen_address": f"127.0.0.1:{bridge_port}",
            "wireguard_address": f"127.0.0.1:{wireguard_port}",
        },
        "wireguard": {
            "interface": "",
            "listen_port": wireguard_port,
            "peer_public_key": gateway["wireguard_public_key"],
            "overlay_address": "",
            "allowed_prefixes": "",
            "routes": "",
        },
        "coordination": {
            "url": f"wss://control.localhost:{https_port}/api/v1/coordination",
            "root_public_key_file": str(sandbox / "root-public.key"),
            "network_id": "sandbox-network",
        },
        "native": {
            "enabled": True,
            "overlay": selected["SANDBOX_OVERLAY_SUBNET"],
            "private": selected["SANDBOX_PRIVATE_SUBNET"],
            "suffix": "sandbox.home.arpa",
        },
        "direct": {"candidates": ""},
        "dns": {"link": "", "enable_forwarding": False},
        "runtime": runtime,
    }
    agent = {
        "node": {
            "state_path": "/var/lib/homeharbor/gateway.json",
            "control_url": "https://control.sandbox:8443",
            "ca_file": "/run/secrets/relay_tls_ca",
            "name": "sandbox-gateway",
        },
        "relay": {
            "websocket_url": "wss://relay.sandbox:8443/relay/udp",
            "session_id": session,
            "destination_device_id": client["device_id"],
            "listen_address": "127.0.0.1:51821",
            "wireguard_address": "127.0.0.1:51820",
        },
        "wireguard": {
            "interface": "wg0",
            "listen_port": 51820,
            "peer_public_key": client["wireguard_public_key"],
            "overlay_address": selected["SANDBOX_GATEWAY_OVERLAY_IP"] + "/32",
            "allowed_prefixes": "",
            "routes": "",
        },
        "coordination": {
            "url": "wss://control.sandbox:8443/api/v1/coordination",
            "root_public_key_file": "/run/secrets/root_public_key",
            "network_id": "sandbox-network",
        },
        "direct": {"candidates": ""},
        # Docker configures IPv4 forwarding before the gateway starts.
        "dns": {"link": "", "enable_forwarding": False},
        "runtime": runtime,
    }
    policy = {
        "version": 1,
        "owner_uid": uid,
        "root_public_key": root,
        "network_id": "sandbox-network",
        "device_id": client["device_id"],
        "local_wireguard_public_key": client["wireguard_public_key"],
        "relay_peer_public_key": gateway["wireguard_public_key"],
        "overlay": selected["SANDBOX_OVERLAY_SUBNET"],
        "private": selected["SANDBOX_PRIVATE_SUBNET"],
        "suffix": "sandbox.home.arpa",
        "bridge_endpoint": f"127.0.0.1:{bridge_port}",
        "wireguard_listen_port": wireguard_port,
    }

    return {
        sandbox / "native-client.toml": (tomlkit.dumps(native).encode(), 0o600),
        sandbox / "gateway.toml": (tomlkit.dumps(agent).encode(), 0o600),
        sandbox / "network-helper.json": (
            (json.dumps(policy, sort_keys=True, indent=2) + "\n").encode(),
            0o600,
        ),
    }


def stored_pair_documents(sandbox, selected, https_port, uid, check_path, ports=None):
    paths = {
        name: sandbox / name
        for name in (
            "client-public.json",
            "gateway-public.json",
            "root-public.key",
            "network-helper.json",
        )
    }
    for path in paths.values():
        check_path(path)

    client = load_public_identity(paths["client-public.json"])
    previous = read_public_file(paths["network-helper.json"])
    if client is None:
        if previous is not None:
            raise ValueError("prepared native pair requires its client public metadata")

        return {}

    gateway = load_public_identity(paths["gateway-public.json"])
    public_root = read_public_file(paths["root-public.key"])
    if gateway is None or public_root is None:
        raise ValueError("native pair requires enrolled gateway and existing public signing root")

    try:
        root = public_root.strip().decode("ascii")
        policy = (
            json.loads(previous, object_pairs_hook=unique_fields) if previous is not None else None
        )
        if policy is not None and not isinstance(policy, dict):
            raise ValueError

        if ports is None:
            if policy is None:
                ports = (51830, 51831)
            else:
                endpoint = policy.get("bridge_endpoint", "")
                if not isinstance(endpoint, str) or not endpoint.startswith("127.0.0.1:"):
                    raise ValueError

                ports = (
                    policy.get("wireguard_listen_port"),
                    int(endpoint.removeprefix("127.0.0.1:")),
                )
    except (UnicodeError, ValueError, TypeError):
        raise ValueError("existing native pair public provisioning is malformed") from None

    documents = pair_documents(sandbox, selected, gateway, client, root, uid, https_port, *ports)
    candidate = json.loads(documents[paths["network-helper.json"]][0])
    if policy is not None and policy != candidate:
        raise ValueError(
            "native pair ownership/scope changed; close the old owner and explicitly reset before reprovisioning"
        )

    return documents
