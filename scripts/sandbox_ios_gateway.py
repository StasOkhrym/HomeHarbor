"""Bind a finite gateway's public identity to the isolated iPhone signed scope."""

import json

import tomlkit
from private_state import complete
from sandbox_identity import (
    MAX_PUBLIC_BYTES,
    load_public_identity,
    unique_fields,
    validate_public_identity,
)
from sandbox_init import render_manifest
from sandbox_ios_config import DIRECTORY, NETWORK_ID, PROFILE_ID, PROJECT
from sandbox_preflight import load_profile


def destinations(owner):
    if owner.project != PROJECT or owner.sandbox != owner.root / DIRECTORY:
        raise ValueError("iPhone gateway requires its separate project and state")

    owner.require_owner()
    paths = [owner.sandbox / "gateway-public.json", owner.sandbox / "initial-snapshot.toml"]
    for path in [*paths, owner.sandbox / "network.env"]:
        owner.check_path(path)
        if path.exists() and not path.is_file():
            raise ValueError("gateway metadata must use regular files")

    if not (owner.sandbox / "network.env").is_file():
        raise ValueError("iPhone network preparation is required")

    return paths


def manifest(owner, identity):
    selected = load_profile(owner.sandbox / "network.env")
    document = tomlkit.parse(render_manifest(selected, identity, template_root=owner.root).decode())
    if len(document["profiles"]) != 1:
        raise ValueError("iPhone fixture needs its single bounded profile")

    document["network_id"] = NETWORK_ID
    document["profiles"][0]["id"] = PROFILE_ID
    document["profiles"][0]["name"] = "iPhone sandbox"
    document["gateways"][0]["name"] = "iPhone sandbox gateway"
    document["services"][0]["description"] = "Manual iPhone packet-path fixture"

    return tomlkit.dumps(document).encode()


def bound_gateway(owner):
    public, snapshot = destinations(owner)
    if not complete([public, snapshot], "iPhone gateway binding"):
        return None

    identity = load_public_identity(public)
    if snapshot.read_bytes() != manifest(owner, identity):
        raise ValueError("existing iPhone gateway manifest differs; explicit review required")

    return identity


def gateway_documents(owner, output):
    previous = bound_gateway(owner)

    try:
        if not isinstance(output, str) or len(output.encode()) > MAX_PUBLIC_BYTES:
            raise ValueError

        identity = validate_public_identity(json.loads(output, object_pairs_hook=unique_fields))
    except (ValueError, TypeError, UnicodeError):
        raise ValueError(
            "gateway did not emit only valid public identity; output withheld"
        ) from None

    if previous is not None and previous != identity:
        raise ValueError("enrolled gateway identity changed; explicit recovery required")

    public, snapshot = destinations(owner)

    return {
        public: ((json.dumps(identity, sort_keys=True) + "\n").encode(), 0o600),
        snapshot: (manifest(owner, identity), 0o600),
    }
