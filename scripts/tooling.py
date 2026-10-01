"""Small shared primitives for repository tooling (Python 3.11+)."""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require_commands(*names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise ValueError("Required commands missing: " + ", ".join(missing))


def port(value, name):
    if not value.isascii() or not value.isdecimal() or not 1024 <= int(value) <= 65535:
        raise ValueError(f"{name} must be an unprivileged TCP port (1024..65535)")

    return int(value)


def atomic_write(path, content, mode=0o600):
    """Publish complete content with the caller's permissions, including unchanged files."""

    if path.is_symlink():
        raise ValueError(f"Refusing to replace symlink: {path.relative_to(ROOT)}")

    if path.exists():
        if path.read_bytes() == content:
            path.chmod(mode)
            return

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None

    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

        temporary.replace(path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def quiet_run(*args):
    """Do not expose credential-bearing stdout/stderr on command failures."""

    result = subprocess.run(args, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"{args[0]} failed (exit {result.returncode})")

    return result.stdout


def cli(main):
    os.chdir(ROOT)

    try:
        return main() or 0
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 2
