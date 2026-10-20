"""Explicit, owned orchestration for the optional macOS sandbox."""

import argparse
import hashlib
import os
import shutil
import sys
import tomllib
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from sandbox_ownership import CommandFailure, SandboxOwnership, quiet_command
from sandbox_preflight import GATEWAY_PROBE_IMAGE, load_profile
from tooling import ROOT, cli, port

PROJECT = "homeharbor-sandbox"
SYSTEM_POLICY = Path("/private/etc/homeharbor/network-helper.json")
SYSTEM_JOURNAL = Path("/private/var/db/homeharbor/client-network.json")


def installed_path_exists(path):
    """Refuse to infer absence from an unreadable privileged parent."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise ValueError("cannot inspect installed native helper state") from None

    return True


class Workflow(SandboxOwnership):
    def __init__(self, root=ROOT, *, run=quiet_command, uid=None):
        super().__init__(root, project=PROJECT, directory=".sandbox", run=run, uid=uid)

    def probe_image(self):
        owner = f"{self.root}\0{self.uid}".encode()
        return f"{GATEWAY_PROBE_IMAGE}:{hashlib.sha256(owner).hexdigest()[:16]}"

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

    def script(self, name, *args, timeout=180):
        return self.command(
            [sys.executable, str(self.root / "scripts" / name), *args],
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

            # Reject occupied pools before creating a Docker image.
            self.script("sandbox_preflight.py", "--check-pools")
            # The kernel capability probe needs this bounded image. Full preflight
            # rechecks pools after the build, before any Compose provisioning.
            probe_image = self.probe_image()
            self.command(
                [
                    "docker",
                    "build",
                    "--target",
                    "probe",
                    "--tag",
                    probe_image,
                    "--file",
                    str(self.root / "deploy/sandbox/Dockerfile.gateway"),
                    str(self.root),
                ],
                timeout=600,
            )
            self.script("sandbox_preflight.py", "--probe-image", probe_image)
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
        if (
            not dirty.exists()
            and not installed_path_exists(SYSTEM_POLICY)
            and not installed_path_exists(SYSTEM_JOURNAL)
        ):
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
                if installed_path_exists(SYSTEM_POLICY) or installed_path_exists(SYSTEM_JOURNAL):
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

    def trust_ca(self, browser="safari", *, target="control"):
        from sandbox_trust import trust_ca

        return trust_ca(self, browser=browser, target=target)


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
    parser.add_argument(
        "--trust-target",
        choices=("control", "site"),
        help="explicit certificate target for trust-ca",
    )
    args = parser.parse_args()
    if args.trust_fingerprint is not None and (args.command, args.action) != ("client", "join"):
        parser.error("--trust-fingerprint is only valid for client join")

    if args.browser is not None and args.command != "trust-ca":
        parser.error("--browser is only valid for trust-ca")

    if args.trust_target is not None and args.command != "trust-ca":
        parser.error("--trust-target is only valid for trust-ca")

    workflow = Workflow()
    if args.command in {"client", "gateway", "prepare", "check"}:
        from sandbox_runtime import dispatch

        return dispatch(workflow, args.command, args.action, args.trust_fingerprint)

    if args.action is not None:
        parser.error("this command takes no extra arguments")

    if args.command == "trust-ca":
        browser = args.browser or os.environ.get("SANDBOX_TRUST_BROWSER", "safari")
        target = args.trust_target or os.environ.get("SANDBOX_TRUST_TARGET", "control")

        return workflow.trust_ca(browser, target=target)

    getattr(workflow, args.command.replace("-", "_"))()


def main():
    try:
        return dispatch_command()
    except CommandFailure as error:
        print(error, file=sys.stderr)
        return error.code


if __name__ == "__main__":
    raise SystemExit(cli(main))
