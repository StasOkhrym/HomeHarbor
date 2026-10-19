"""Verify real SMTP only against owned disposable authenticated TLS Mailpit captures."""

import base64
import json
import os
import secrets
import signal
import socket
import subprocess
import tempfile
import uuid
from pathlib import Path

from process_owner import run
from tls_material import issue, issue_authority
from tooling import cli, require_commands

CONTRACT = "TestMailpitSMTPVerifiedTLSAndMIME"


def validate_events(stream):
    expected = {CONTRACT, *(CONTRACT + "/" + mode for mode in ("starttls", "tls"))}
    expected.update(
        CONTRACT + "/" + mode + "/" + fault
        for mode in ("starttls", "tls")
        for fault in ("password", "authority", "hostname")
    )
    passed = set()
    for line in stream:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            raise ValueError("SMTP contract produced invalid test events") from None

        if event.get("Output"):
            print(event["Output"], end="", flush=True)

        if event.get("Action") == "skip":
            raise ValueError("Required Mailpit SMTP contract was skipped")

        if event.get("Action") == "pass":
            passed.add(event.get("Test", ""))

    if not expected.issubset(passed):
        raise ValueError("Required Mailpit SMTP modes or TLS/auth rejection contracts did not pass")


def capture(directory, ports, certificate, key, auth):
    services = {}
    for index, mode in enumerate(("starttls", "tls")):
        environment = {
            "MP_DATABASE": "/tmp/mailpit.db",
            "MP_DISABLE_VERSION_CHECK": "true",
            "MP_SMTP_TLS_CERT": "/run/secrets/smtp_cert",
            "MP_SMTP_TLS_KEY": "/run/secrets/smtp_key",
            "MP_SMTP_AUTH_FILE": "/run/secrets/smtp_auth",
            "MP_ALLOWED_HOSTS": "localhost",
            "MP_SMTP_REQUIRE_STARTTLS" if mode == "starttls" else "MP_SMTP_REQUIRE_TLS": "true",
        }
        services[mode] = {
            "image": "axllent/mailpit:v1.31.6",
            "user": f"{os.getuid()}:{os.getgid()}",
            "environment": environment,
            "secrets": ["smtp_cert", "smtp_key", "smtp_auth"],
            "ports": [
                f"127.0.0.1:{ports[index * 2]}:1025",
                f"127.0.0.1:{ports[index * 2 + 1]}:8025",
            ],
            "healthcheck": {
                "test": ["CMD", "/mailpit", "readyz"],
                "interval": "2s",
                "timeout": "2s",
                "retries": 20,
            },
            "read_only": True,
            "tmpfs": ["/tmp:size=64m"],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "mem_limit": "256m",
        }

    config = directory / "compose.json"
    config.write_text(
        json.dumps(
            {
                "services": services,
                "secrets": {
                    name: {"file": str(path)}
                    for name, path in (
                        ("smtp_cert", certificate),
                        ("smtp_key", key),
                        ("smtp_auth", auth),
                    )
                },
            }
        )
    )
    return config


def contracts(env):
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        result = run(
            [
                "go",
                "test",
                "-race",
                "-json",
                "./internal/platform/mail/smtp",
                "-run",
                "^" + CONTRACT + "$",
                "-count=1",
                "-timeout=60s",
            ],
            env,
            stdout=output,
        )
        output.seek(0)
        if result:
            # Test failure output contains only owned fixture diagnostics. Keep
            # the original Go status even if a killed process left partial JSON.
            for line in output:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("Output"):
                    print(event["Output"], end="")

            return result

        validate_events(output)

    print("Owned Mailpit STARTTLS/TLS, MIME and credential/CA/hostname rejection contracts passed")
    return 0


def main(contract_runner=None, environment=None):
    contract_runner = contract_runner or contracts
    require_commands("docker", "go", "openssl")
    if os.getuid() == 0:
        raise ValueError("Run SMTP capture integration as a non-root user")

    project = "homeharbor-smtp-integration-" + uuid.uuid4().hex[:12]
    result = 1

    with tempfile.TemporaryDirectory(prefix=project + "-") as temporary:
        directory = Path(temporary).resolve()
        ca, private_ca = issue_authority(directory, "HomeHarbor SMTP integration CA")
        certificate, key = issue(directory, "smtp", ca, private_ca, ["localhost", "mailpit"])
        password = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        password_file, auth = directory / "password", directory / "auth"
        password_file.write_text(password)
        auth.write_text("homeharbor:" + password + "\n")
        password_file.chmod(0o600)
        auth.chmod(0o600)
        reservations = []

        try:
            for _ in range(4):
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                reservations.append(listener)

            ports = [listener.getsockname()[1] for listener in reservations]
            config = capture(directory, ports, certificate, key, auth)
        finally:
            for listener in reservations:
                listener.close()

        env = {
            **(os.environ if environment is None else environment),
            "TEST_MAILPIT_CAPTURE": "1",
            "TEST_MAILPIT_CA_FILE": str(ca),
            "TEST_MAILPIT_PASSWORD_FILE": str(password_file),
            "TEST_MAILPIT_STARTTLS_PORT": str(ports[0]),
            "TEST_MAILPIT_STARTTLS_URL": f"http://127.0.0.1:{ports[1]}",
            "TEST_MAILPIT_TLS_PORT": str(ports[2]),
            "TEST_MAILPIT_TLS_URL": f"http://127.0.0.1:{ports[3]}",
        }
        compose = ["docker", "compose", "--project-name", project, "--file", str(config)]

        try:
            result = run(
                [*compose, "up", "--detach", "--wait", "--wait-timeout", "60"],
                env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result:
                print(
                    "Owned Mailpit capture failed to start; no application services were selected"
                )
            else:
                result = contract_runner(env)
        finally:
            for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, signal.SIG_IGN)

            try:
                cleanup = subprocess.run(
                    [*compose, "down", "--volumes", "--remove-orphans"],
                    env=env,
                    capture_output=True,
                    timeout=45,
                    check=False,
                )
                if cleanup.returncode:
                    print("Owned Mailpit cleanup failed")
                    result = result or cleanup.returncode
            except (OSError, subprocess.TimeoutExpired):
                print("Owned Mailpit cleanup unavailable")
                result = result or 1

    return result


if __name__ == "__main__":
    raise SystemExit(cli(main))
