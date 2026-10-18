"""Prepare private Mailpit-only development trust without changing app or host trust."""

import base64
import os
import secrets
import tempfile
from pathlib import Path

from private_state import complete
from tls_material import issue, issue_authority, verify_pair
from tooling import ROOT, atomic_write, cli, port, require_commands


def initialize():
    require_commands("openssl")
    capture_port = port(os.environ.get("DEV_MAILPIT_PORT", "8025"), "DEV_MAILPIT_PORT")
    http_port = port(
        os.environ.get("PROXY_HTTP_PORT", os.environ.get("DEV_HTTP_PORT", "8088")),
        "PROXY_HTTP_PORT",
    )
    https_port = port(
        os.environ.get("PROXY_HTTPS_PORT", os.environ.get("DEV_HTTPS_PORT", "8443")),
        "PROXY_HTTPS_PORT",
    )
    if capture_port in (http_port, https_port):
        raise ValueError("DEV_MAILPIT_PORT must be an unprivileged port distinct from HTTP/HTTPS")

    directory, local = ROOT / "secrets", ROOT / ".local"
    ca, cert, key = [directory / f"smtp_tls_{part}" for part in ("ca", "cert", "key")]
    ca_key = local / "smtp-ca-key.pem"
    has_tls = complete([ca, cert, key, ca_key], "Development SMTP TLS")
    password_file, auth_file = directory / "smtp_password", directory / "smtp_auth"
    has_credentials = complete([password_file, auth_file], "Development SMTP credentials")
    password = (
        password_file.read_bytes() if has_credentials else base64.b64encode(secrets.token_bytes(32))
    )

    try:
        valid_password = (
            len(password) == 44 and len(base64.b64decode(password, validate=True)) == 32
        )
    except ValueError:
        valid_password = False

    if not valid_password:
        raise ValueError("Development SMTP password must be the original bounded credential")

    authentication = b"homeharbor:" + password + b"\n"
    if has_credentials and auth_file.read_bytes() != authentication:
        raise ValueError("Development SMTP auth/password files differ; restore the matching pair")

    pending = {password_file: (password, 0o600), auth_file: (authentication, 0o600)}

    with tempfile.TemporaryDirectory(prefix="homeharbor-mail-init-") as scratch:
        if has_tls:
            verify_pair(cert, key, ca, ["mailpit", "localhost"])
            pending.update(
                {
                    path: (path.read_bytes(), mode)
                    for path, mode in ((ca, 0o644), (cert, 0o644), (key, 0o600), (ca_key, 0o600))
                }
            )
        else:
            authority, private = issue_authority(Path(scratch), "HomeHarbor Development Mail CA")
            certificate, private_key = issue(
                Path(scratch), "smtp", authority, private, ["mailpit", "localhost"]
            )
            for destination, source, mode in (
                (ca, authority, 0o644),
                (ca_key, private, 0o600),
                (cert, certificate, 0o644),
                (key, private_key, 0o600),
            ):
                pending[destination] = (source.read_bytes(), mode)

    # Validate every destination before publishing the first staged file.
    for path in pending:
        if path.is_symlink() or any(
            parent.is_symlink() for parent in path.parents if parent != ROOT
        ):
            raise ValueError("Refusing development SMTP state through a symlink")

    for path, (content, mode) in pending.items():
        atomic_write(path, content, mode)

    print(f"Private mail capture ready: http://127.0.0.1:{capture_port}")


if __name__ == "__main__":
    raise SystemExit(cli(initialize))
