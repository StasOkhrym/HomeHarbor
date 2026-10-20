"""Stage isolated manual iPhone trust/keys; never publish or rotate partial state."""

import base64
import binascii
import secrets
import tempfile
from pathlib import Path

from dev_init import SECRET_BYTES
from private_state import complete
from sandbox_ios_config import (
    ADMIN_HOST,
    CONTROL_HOST,
    DIRECTORY,
    PROJECT,
    RELAY_HOST,
    LANEndpoints,
)
from sandbox_ownership import SandboxOwnership
from tls_material import issue, issue_authority, same_authority, verify_pair


def public_root(raw: bytes) -> bytes:
    value = raw.strip()

    try:
        key = base64.b64decode(value + b"=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("companion must return only a canonical public root") from None

    if len(key) != 32 or not any(key) or base64.urlsafe_b64encode(key).rstrip(b"=") != value:
        raise ValueError("companion must return only a canonical public root")

    return value + b"\n"


def material_documents(owner: SandboxOwnership, endpoints: LANEndpoints):
    """Call under the owner lock; validate all candidates before publication.

    Only the existing Go init-root command creates the encrypted companion key.
    TLS uses the same strict helper as other local flows, with its own CAs.
    """

    if owner.project != PROJECT or owner.sandbox != owner.root / DIRECTORY:
        raise ValueError("iPhone material requires its separate project and private state")

    owner.require_owner()
    state = owner.sandbox
    secret_dir = state / "secrets"
    control_paths = [
        secret_dir / "relay_tls_ca",
        state / "relay-ca-key.pem",
        secret_dir / "relay_tls_cert",
        secret_dir / "relay_tls_key",
        secret_dir / "frontend_tls_cert",
        secret_dir / "frontend_tls_key",
    ]
    site_paths = [
        secret_dir / "site_tls_ca",
        state / "site-ca-key.pem",
        secret_dir / "site_tls_cert",
        secret_dir / "site_tls_key",
    ]
    root_paths = [
        state / "root-key.age",
        state / "root-public.key",
        state / "root-passphrase",
        secret_dir / "root_public_key",
    ]
    for path in [
        *control_paths,
        *site_paths,
        *root_paths,
        *(secret_dir / name for name in SECRET_BYTES),
    ]:
        owner.check_path(path)

    has_control = complete(control_paths, "iPhone sandbox control TLS")
    has_site = complete(site_paths, "iPhone sandbox site TLS")
    has_root = complete(root_paths, "iPhone sandbox companion root")
    documents = {}
    for name, size in SECRET_BYTES.items():
        path = secret_dir / name
        content = (
            path.read_bytes() if path.exists() else base64.b64encode(secrets.token_bytes(size))
        )

        try:
            value = base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("iPhone sandbox service secret is malformed") from None

        if len(value) != size or base64.b64encode(value) != content:
            raise ValueError("iPhone sandbox service secret is malformed")

        documents[path] = (content, 0o600)

    def retain(destinations, sources, modes):
        for destination, source, mode in zip(destinations, sources, modes, strict=True):
            documents[destination] = (source.read_bytes(), mode)

    with tempfile.TemporaryDirectory(prefix="homeharbor-ios-material-") as temporary:
        scratch = Path(temporary)
        names = [ADMIN_HOST, CONTROL_HOST, RELAY_HOST]
        if has_control:
            ca, ca_key, relay, relay_key, frontend, frontend_key = control_paths
            verify_pair(ca, ca_key, ca, [])
            verify_pair(relay, relay_key, ca, ["relay"], exact_names=True)
            verify_pair(
                frontend,
                frontend_key,
                ca,
                names,
                ip_addresses=[endpoints.address],
                exact_names=True,
            )
            sources = control_paths
        else:
            staging = scratch / "control"
            staging.mkdir(mode=0o700)
            ca, ca_key = issue_authority(staging, "HomeHarbor iPhone Control CA")
            relay, relay_key = issue(staging, "relay", ca, ca_key, ["relay"])
            frontend, frontend_key = issue(
                staging, "frontend", ca, ca_key, names, ip_addresses=[endpoints.address]
            )
            sources = [ca, ca_key, relay, relay_key, frontend, frontend_key]

        retain(control_paths, sources, [0o644, 0o600, 0o644, 0o600, 0o644, 0o600])

        if has_site:
            site_ca, site_ca_key, site, site_key = site_paths
            verify_pair(site_ca, site_ca_key, site_ca, [])
            verify_pair(site, site_key, site_ca, ["site.sandbox.home.arpa"], exact_names=True)
            sources = site_paths
        else:
            staging = scratch / "site"
            staging.mkdir(mode=0o700)
            site_ca, site_ca_key = issue_authority(staging, "HomeHarbor iPhone Private Site CA")
            site, site_key = issue(
                staging, "site", site_ca, site_ca_key, ["site.sandbox.home.arpa"]
            )
            sources = [site_ca, site_ca_key, site, site_key]

        if same_authority(ca, site_ca):
            raise ValueError("iPhone private site must use a separate control authority")

        retain(site_paths, sources, [0o644, 0o600, 0o644, 0o600])

        if has_root:
            root, public, phrase, mounted = root_paths
            canonical = public_root(public.read_bytes())
            if mounted.read_bytes() != public.read_bytes() or canonical != public.read_bytes():
                raise ValueError("iPhone sandbox public root files do not match")

            retain(root_paths, root_paths, [0o600, 0o644, 0o600, 0o644])
        else:
            phrase, root = scratch / "phrase", scratch / "root-key.age"
            phrase.write_bytes(base64.b64encode(secrets.token_bytes(32)))
            phrase.chmod(0o600)
            output = owner.command(
                [
                    "go",
                    "-C",
                    str(owner.root),
                    "run",
                    "./cmd/admin",
                    "init-root",
                    "--key",
                    str(root),
                    "--passphrase-file",
                    str(phrase),
                ],
                timeout=120,
            )

            try:
                canonical = public_root(output.encode("ascii"))
            except UnicodeError:
                raise ValueError("companion must return only a canonical public root") from None

            if not root.is_file() or root.is_symlink() or not root.read_bytes():
                raise ValueError("companion encrypted root creation was incomplete")

            documents[root_paths[0]] = (root.read_bytes(), 0o600)
            documents[root_paths[1]] = (canonical, 0o644)
            documents[root_paths[2]] = (phrase.read_bytes(), 0o600)
            documents[root_paths[3]] = (canonical, 0o644)

    return documents
