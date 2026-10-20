"""Owned private state and Docker inventory for explicit manual sandbox flows.

This module never provisions Compose or invokes native networking helpers.
"""

import contextlib
import fcntl
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from sandbox_identity import read_public_file, unique_fields
from tooling import atomic_write

WORKSPACE_LABEL = "io.homeharbor.sandbox.workspace"
OWNER_LABEL = "io.homeharbor.sandbox.owner"


class CommandFailure(ValueError):
    def __init__(self, code):
        self.code = code if code > 0 else 128 - code
        super().__init__(f"sandbox command failed (exit {self.code}); captured output withheld")


def quiet_command(args, *, env=None, timeout=180, input=None):
    """Credential-bearing command output never becomes a workflow diagnostic."""

    try:
        result = subprocess.run(
            args, env=env, input=input, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        raise CommandFailure(124) from None

    if result.returncode:
        raise CommandFailure(result.returncode)

    return result.stdout


class SandboxOwnership:
    def __init__(self, root: Path, *, project: str, directory: str, run=quiet_command, uid=None):
        if not re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)*", project) or len(project) > 63:
            raise ValueError("sandbox project must be a bounded lowercase Compose name")
        if (
            not directory.startswith(".")
            or directory in {".", ".."}
            or Path(directory).parts != (directory,)
        ):
            raise ValueError("sandbox state must be a private directory directly in the workspace")

        self.root = root.resolve()
        self.project = project
        self.sandbox = self.root / directory
        self.owner_file = self.sandbox / "workflow-owner.json"
        self.run = run
        self.uid = os.getuid() if uid is None else uid
        if self.uid <= 0:
            raise ValueError("run the sandbox as a non-root user")

    @property
    def owner(self):
        return {"version": 1, "project": self.project, "workspace": str(self.root), "uid": self.uid}

    def check_path(self, path):
        if not path.is_relative_to(self.sandbox):
            raise ValueError("sandbox path is outside owned state")

        for item in (path, *path.parents):
            if item == self.root:
                break
            if item.is_symlink():
                raise ValueError("sandbox path contains a symlink")
            if item.exists() and item != path and not item.is_dir():
                raise ValueError("sandbox parent must be a directory")

        if path.exists() and not (path.is_file() or path.is_dir()):
            raise ValueError("sandbox state must be a regular file or directory")

    @contextlib.contextmanager
    def lock(self, name="workflow.lock"):
        self.check_path(self.sandbox / name)
        self.sandbox.mkdir(mode=0o700, exist_ok=True)
        path = self.sandbox / name
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("sandbox lock must be an owned regular file")

            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError(
                    "sandbox workflow is active; wait for its current command"
                ) from None

            yield fd
        finally:
            os.close(fd)

    def require_owner(self):
        self.check_path(self.owner_file)
        raw = read_public_file(self.owner_file)
        if raw is None:
            raise ValueError("sandbox ownership is missing; refusing unowned state")

        try:
            value = json.loads(raw, object_pairs_hook=unique_fields)
        except ValueError:
            raise ValueError("sandbox ownership record is malformed") from None

        if value != self.owner:
            raise ValueError("sandbox ownership does not match this workspace and user")

    def command(self, args, **kwargs):
        try:
            return self.run(args, **kwargs)
        except CommandFailure:
            raise
        except (ValueError, OSError):
            raise ValueError("sandbox command failed; captured output withheld") from None

    def inventory(self):
        resources = {}
        for kind, listing in (
            ("container", ["docker", "ps", "--all", "--quiet"]),
            ("network", ["docker", "network", "ls", "--quiet"]),
            ("volume", ["docker", "volume", "ls", "--quiet"]),
        ):
            # Compose may adopt an existing named volume without project labels.
            # Inspect both selections separately; Docker filter combination varies
            # across resource kinds, so an AND would miss an unlabeled collision.
            ids = []
            for selection in (
                f"label=com.docker.compose.project={self.project}",
                f"name={self.project}",
            ):
                ids.extend(self.command([*listing, "--filter", selection], timeout=30).split())

            ids = list(dict.fromkeys(ids))
            inspect = ["docker", "inspect"] if kind == "container" else ["docker", kind, "inspect"]

            try:
                items = json.loads(self.command([*inspect, *ids], timeout=30)) if ids else []
            except ValueError:
                raise ValueError("cannot read sandbox Docker ownership") from None

            if not isinstance(items, list) or len(items) != len(ids):
                raise ValueError("sandbox Docker ownership inspection is incomplete")

            for item in items:
                labels = (
                    item.get("Config", {}).get("Labels")
                    if kind == "container"
                    else item.get("Labels")
                )
                if not labels or any(
                    labels.get(key) != expected
                    for key, expected in (
                        ("com.docker.compose.project", self.project),
                        (WORKSPACE_LABEL, str(self.root)),
                        (OWNER_LABEL, str(self.uid)),
                    )
                ):
                    raise ValueError(
                        f"foreign {kind} or missing sandbox ownership; refusing operation"
                    )

            resources[kind] = items

        return resources

    def create_owner(self):
        self.check_path(self.owner_file)
        if self.owner_file.exists():
            self.require_owner()
            self.inventory()
            return

        resources = self.inventory()
        if any(resources.values()):
            raise ValueError("existing project resources require their original sandbox ownership")

        self.check_path(self.sandbox)
        if self.sandbox.exists() and any(
            p.name not in {"workflow.lock", "archives"} for p in self.sandbox.iterdir()
        ):
            raise ValueError("existing unowned sandbox state requires explicit review")

        self.sandbox.mkdir(mode=0o700, exist_ok=True)
        self.sandbox.chmod(0o700)
        atomic_write(self.owner_file, (json.dumps(self.owner, sort_keys=True) + "\n").encode())
