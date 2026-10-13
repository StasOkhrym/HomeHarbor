"""Validate the public-only output of finite node enrollment."""

import base64
import binascii
import json
import os
import re
import stat
from pathlib import Path

FIELDS = {"device_id", "identity_public_key", "wireguard_public_key"}
MAX_PUBLIC_BYTES = 8192


def validate_public_identity(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != FIELDS
        or any(not isinstance(item, str) for item in value.values())
    ):
        raise ValueError("node metadata must contain exactly three public identity fields")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value["device_id"]):
        raise ValueError("node metadata has an invalid device ID")

    try:
        identity = base64.b64decode(
            value["identity_public_key"] + "=", altchars=b"-_", validate=True
        )
        wireguard = base64.b64decode(value["wireguard_public_key"], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("node metadata has invalid public key encoding") from None

    if (
        len(identity) != 32
        or len(wireguard) != 32
        or not any(identity)
        or not any(wireguard)
        or base64.urlsafe_b64encode(identity).decode().rstrip("=") != value["identity_public_key"]
        or base64.b64encode(wireguard).decode() != value["wireguard_public_key"]
    ):
        raise ValueError("node metadata requires canonical nonzero public keys")

    return dict(value)


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("node metadata contains duplicate fields")

        result[key] = value

    return result


def load_public_identity(path: Path) -> dict[str, str] | None:
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("node public metadata must not use symlinks")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PUBLIC_BYTES:
            raise ValueError("node public metadata must be a bounded regular file")
        content = stream.read(MAX_PUBLIC_BYTES + 1)
    if len(content) > MAX_PUBLIC_BYTES:
        raise ValueError("node public metadata is oversized")
    try:
        value = json.loads(content, object_pairs_hook=unique_fields)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("node public metadata is malformed") from None
    return validate_public_identity(value)
