"""Bind enrolled gateway public metadata into the isolated initial manifest."""

import argparse

from sandbox_init import SANDBOX, check_destination, gateway_public_identity, resolve_manifest
from sandbox_preflight import NETWORK_FILE, load_profile
from tooling import atomic_write, cli


def bind_gateway():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if not NETWORK_FILE.is_file():
        raise ValueError("sandbox preflight and initialization are required before binding")

    public = gateway_public_identity()
    if public is None:
        raise ValueError("gateway public identity is required; run agent enroll first")

    manifest = SANDBOX / "initial-snapshot.toml"
    check_destination(manifest)
    content = resolve_manifest(
        manifest.read_bytes() if manifest.exists() else None, load_profile(), public
    )
    atomic_write(manifest, content, 0o600)
    print(
        "Enrolled gateway bound to the sandbox initial manifest. Companion signing is still required."
    )


if __name__ == "__main__":
    raise SystemExit(cli(bind_gateway))
