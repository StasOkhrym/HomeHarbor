"""Explicit, owned orchestration for the optional macOS sandbox."""

import argparse
import contextlib
import fcntl
import json
import os
import shutil
import stat
import subprocess
import sys
import tomllib
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from sandbox_identity import read_public_file, unique_fields
from sandbox_preflight import load_profile
from tooling import ROOT, atomic_write, cli, port

PROJECT = "homeharbor-sandbox"
WORKSPACE_LABEL = "io.homeharbor.sandbox.workspace"
OWNER_LABEL = "io.homeharbor.sandbox.owner"
SYSTEM_POLICY = Path("/private/etc/homeharbor/network-helper.json")
SYSTEM_JOURNAL = Path("/private/var/db/homeharbor/client-network.json")


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


class Workflow:
    def __init__(self, root=ROOT, *, run=quiet_command, uid=None):
        self.root = root.resolve()
        self.sandbox = self.root / ".sandbox"
        self.owner_file = self.sandbox / "workflow-owner.json"
        self.run = run
        self.uid = os.getuid() if uid is None else uid
        if self.uid <= 0:
            raise ValueError("run the sandbox as a non-root user")

    @property
    def owner(self):
        return {"version": 1, "project": PROJECT, "workspace": str(self.root), "uid": self.uid}

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
            for selection in (f"label=com.docker.compose.project={PROJECT}", f"name={PROJECT}"):
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
                        ("com.docker.compose.project", PROJECT),
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
        config = self.sandbox / "control.toml"
        if config.exists():
            self.check_path(config)

            try:
                origin = urlsplit(tomllib.loads(config.read_text())["server"]["public_url"])
                if origin.scheme != "https" or origin.hostname != "control.localhost":
                    raise ValueError

                env["SANDBOX_HTTPS_PORT"] = str(port(str(origin.port), "sandbox HTTPS port"))
            except (KeyError, TypeError, ValueError):
                raise ValueError("sandbox control must have its generated HTTPS origin") from None

        return env

    def compose(self, *args, timeout=180, input=None):
        env_file = self.sandbox / "network.env"
        self.check_path(env_file)
        if env_file.exists():
            load_profile(env_file)

        return self.command(
            [
                "docker",
                "compose",
                "--project-name",
                PROJECT,
                "--project-directory",
                str(self.root / "deploy"),
                "--env-file",
                str(env_file) if env_file.exists() else "/dev/null",
                "--file",
                str(self.root / "deploy/compose.sandbox.yaml"),
                "--profile",
                "native-client",
                *args,
            ],
            env=self.environment(),
            timeout=timeout,
            input=input,
        )

    def script(self, name, *, timeout=180):
        return self.command(
            [sys.executable, str(self.root / "scripts" / name)],
            env=self.environment(),
            timeout=timeout,
        )

    def up(self):
        if sys.platform != "darwin":
            raise ValueError("the optional native sandbox requires macOS")
        with self.lock():
            self.create_owner()
            resources = self.inventory()
            if resources["container"] or resources["network"]:
                raise ValueError("existing sandbox containers/networks; run sandbox-down before up")
            # Build the bounded kernel probe before selecting pools or issuing trust.
            self.command(
                [
                    "docker",
                    "build",
                    "--target",
                    "probe",
                    "--tag",
                    "homeharbor-sandbox-gateway-probe",
                    "--file",
                    str(self.root / "deploy/sandbox/Dockerfile.gateway"),
                    str(self.root),
                ],
                timeout=600,
            )
            self.script("sandbox_preflight.py")
            self.script("sandbox_init.py")
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
            print(
                f"Sandbox ready: https://control.localhost:{self.environment().get('SANDBOX_HTTPS_PORT', '8443')}/admin/login"
            )
            print(
                "Next: explicit browser CA trust, admin login, gateway enrollment and companion signing."
            )

    def cleanup_native(self):
        dirty = self.sandbox / "native-dirty"
        self.check_path(dirty)
        if not dirty.exists() and not SYSTEM_POLICY.exists() and not SYSTEM_JOURNAL.exists():
            return
        config = self.sandbox / "native-client.toml"
        binary = self.sandbox / "bin/client"
        for path in (config, binary):
            self.check_path(path)
            if not path.is_file():
                raise ValueError("native cleanup requires existing config and client binary")
        self.command([str(binary), "network-close", "--config", str(config)], timeout=45)
        dirty.unlink(missing_ok=True)

    def down(self):
        self.require_owner()

        with self.lock():
            self.inventory()
            self.stop_client()
            self.cleanup_native()
            self.compose("down", "--timeout", "140", timeout=180)

        print("Owned sandbox stopped. Identities and volumes preserved.")

    def reset(self):
        self.require_owner()
        with self.lock():
            resources = self.inventory()
            if any(item.get("State", {}).get("Running") for item in resources["container"]):
                raise ValueError("sandbox is running; sandbox-down is required before reset")
            # Validate the entire local tree before any destructive Docker operation.
            for path in self.sandbox.rglob("*"):
                self.check_path(path)
            with self.lock("client-runtime.lock"):
                self.cleanup_native()
                if SYSTEM_POLICY.exists() or SYSTEM_JOURNAL.exists():
                    raise ValueError(
                        "retire the installed native helper binding before resetting its identity"
                    )
                self.compose("down", "--volumes", "--timeout", "140", timeout=180)
                archive = self.sandbox / "archives" / uuid.uuid4().hex
                archive.mkdir(parents=True, mode=0o700)
                for path in self.sandbox.iterdir():
                    if path.name not in {"archives", "workflow.lock", "client-runtime.lock"}:
                        shutil.move(path, archive / path.name)
        print(
            "Stopped sandbox volumes removed. Prior identity/trust archived privately inside .sandbox."
        )

    def status(self):
        self.require_owner()
        resources = self.inventory()
        print(f"Sandbox owner: {self.root} (uid {self.uid})")
        print(
            "Docker resources: "
            + ", ".join(f"{kind}={len(items)}" for kind, items in resources.items())
        )
        print(
            "Native cleanup pending: "
            + ("yes" if (self.sandbox / "native-dirty").exists() else "no recorded workflow apply")
        )
        print(
            "Status does not prove signed authorization or packet reachability; use sandbox-check."
        )

    def logs(self):
        self.require_owner()
        self.inventory()
        # No companion outputs, private enrollment inputs, raw headers, environment,
        # state, or Compose config are exposed through this command.
        output = self.compose("logs", "--no-color", "--tail", "100", "control", "relay", "gateway")
        from sandbox_diagnostics import public_log_lines

        print("\n".join(public_log_lines(output)))

    def stop_client(self):
        from sandbox_runtime import stop_client

        stop_client(self)

    def trust_ca(self, browser="safari"):
        from sandbox_trust import trust_ca

        return trust_ca(self, browser=browser)


def dispatch_command():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "up",
            "client",
            "gateway",
            "prepare",
            "status",
            "logs",
            "check",
            "down",
            "reset",
            "trust-ca",
        ),
    )
    parser.add_argument("action", nargs="?")
    parser.add_argument(
        "--trust-fingerprint", help="public out-of-band SHA-256 trust fingerprint for client join"
    )
    parser.add_argument(
        "--browser", choices=("safari", "chrome"), help="explicit browser trust mode for trust-ca"
    )
    args = parser.parse_args()
    if args.trust_fingerprint is not None and (args.command, args.action) != ("client", "join"):
        parser.error("--trust-fingerprint is only valid for client join")
    if args.browser is not None and args.command != "trust-ca":
        parser.error("--browser is only valid for trust-ca")
    workflow = Workflow()
    if args.command in {"client", "gateway", "prepare", "check"}:
        from sandbox_runtime import dispatch

        return dispatch(workflow, args.command, args.action, args.trust_fingerprint)
    if args.action is not None:
        parser.error("this command takes no extra arguments")
    if args.command == "trust-ca":
        return workflow.trust_ca(args.browser or os.environ.get("SANDBOX_TRUST_BROWSER", "safari"))
    getattr(workflow, args.command.replace("-", "_"))()


def main():
    try:
        return dispatch_command()
    except CommandFailure as error:
        print(error, file=sys.stderr)
        return error.code


if __name__ == "__main__":
    raise SystemExit(cli(main))
