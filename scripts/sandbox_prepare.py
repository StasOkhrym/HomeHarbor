"""Prepare public-only native pair configs and a reviewable helper policy candidate."""

import argparse
import os
import tomllib
from urllib.parse import urlsplit

from sandbox_init import SANDBOX, check_destination
from sandbox_pair import stored_pair_documents
from sandbox_preflight import NETWORK_FILE, load_profile
from tooling import atomic_write, cli, port


def prepare():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wireguard-port", type=int)
    parser.add_argument("--bridge-port", type=int)
    args = parser.parse_args()
    if (args.wireguard_port is None) != (args.bridge_port is None):
        raise ValueError("provide both native ports or neither")

    ports = (args.wireguard_port, args.bridge_port) if args.wireguard_port is not None else None
    if not NETWORK_FILE.is_file():
        raise ValueError("sandbox preflight and initialization are required")

    control = SANDBOX / "control.toml"
    check_destination(control)

    try:
        origin = urlsplit(tomllib.loads(control.read_text())["server"]["public_url"])
        if (
            origin.scheme != "https"
            or origin.hostname != "control.localhost"
            or origin.username is not None
            or origin.path
            or origin.query
            or origin.fragment
        ):
            raise ValueError

        https_port = port(str(origin.port), "sandbox control port")
    except (KeyError, TypeError, ValueError):
        raise ValueError("sandbox control requires its generated HTTPS host origin") from None

    pending = stored_pair_documents(
        SANDBOX, load_profile(), https_port, os.getuid(), check_destination, ports
    )
    if len(pending) != 3:
        raise ValueError(
            "export joined client and gateway public identities before native preparation"
        )

    for path in pending:
        check_destination(path)

    for path, (content, mode) in pending.items():
        atomic_write(path, content, mode)

    print(
        "Native pair config and public helper policy candidate prepared. Explicit privileged installation is still required."
    )


if __name__ == "__main__":
    raise SystemExit(cli(prepare))
