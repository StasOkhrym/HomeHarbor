"""Run mandatory contracts against disposable services, or explicit external test URLs."""

import argparse
import base64
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from tooling import ROOT, cli, port, require_commands

REQUIRED = {
    "PostgreSQL",
    "Redis",
    "Redis browser sessions",
    "migration advisory lock",
    "credential recovery Redis",
    "credential recovery SQL",
}
ADAPTERS = {
    f"control/{module}/storage"
    for module in (
        "audit",
        "devices",
        "identity",
        "invites",
        "policy",
        "routes",
        "services",
        "snapshots",
    )
}
ADAPTERS.add("app/control/storage")


def test_urls(postgres_password, redis_password, postgres_port, redis_port):
    return {
        "TEST_DATABASE_URL": f"postgres://homeharbor:{quote(postgres_password, safe='')}@127.0.0.1:{postgres_port}/homeharbor?sslmode=disable",
        "TEST_REDIS_URL": f"redis://:{quote(redis_password, safe='')}@127.0.0.1:{redis_port}/0",
    }


def run(args, env, **kwargs):
    """Terminate the complete child process group when interrupted."""
    process = None
    pending_signal = None

    def defer_signal(signum, _frame):
        nonlocal pending_signal
        if pending_signal is None:
            pending_signal = signum

    # Install before spawning: no signal may unwind the ownership/cleanup
    # boundary. Polling observes cancellation; handlers only record it.
    previous_handlers = {
        sig: signal.signal(sig, defer_signal)
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    try:
        process = subprocess.Popen(args, env=env, start_new_session=True, **kwargs)
        while pending_signal is None:
            try:
                status = process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                continue
            if pending_signal is None:
                return status
        raise SystemExit(128 + pending_signal)
    finally:
        # The session belongs to this invocation, including descendants whose
        # parent has already exited. Parent poll() alone cannot prove cleanup.
        try:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                while time.monotonic() < deadline:
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        break
                    time.sleep(0.05)
                else:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait()
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
        # Preserve an already propagating exception/cancellation. A first
        # signal arriving only during cleanup still determines the exit status.
        if pending_signal is not None and sys.exc_info()[0] is None:
            raise SystemExit(128 + pending_signal)


def validate_events(stream):
    passed, adapters, skipped = set(), set(), []
    for line in stream:
        event = json.loads(line)
        if event.get("Output"):
            print(event["Output"], end="", flush=True)
        name, package = event.get("Test", ""), event.get("Package", "")
        if event.get("Action") == "skip" and name:
            skipped.append(f"{package}/{name}")
        if event.get("Action") != "pass" or not name or "/" in name:
            continue
        if name == "TestRedisRecoveryChallengeConsumedOnceAcrossReplicas" and package.endswith(
            "/control/workflows"
        ):
            passed.add("credential recovery Redis")
        if name == "TestPostgresRecoveredCredentialInvalidatesOldCredential" and package.endswith(
            "/control/devices/storage"
        ):
            passed.add("credential recovery SQL")
        if name.startswith("TestPostgres") and "/control/" in package:
            passed.add("PostgreSQL")
            if package.endswith("/storage"):
                adapters.add(package.split("/internal/", 1)[-1])
        if name.startswith("TestRedis") and package.endswith("/platform/redissecurity"):
            passed.add("Redis")
        if name == "TestRedisSessionSharedTTLAndRevoke" and package.endswith(
            "/control/identity/redis"
        ):
            passed.add("Redis browser sessions")
        if "AdvisoryLock" in name and package.endswith("/migrations"):
            passed.add("migration advisory lock")
    if skipped:
        raise ValueError("Required integration tests skipped: " + ", ".join(skipped))
    if missing := REQUIRED - passed:
        raise ValueError("Required integration tests did not run: " + ", ".join(sorted(missing)))
    if missing := ADAPTERS - adapters:
        raise ValueError("SQL adapters without executed contracts: " + ", ".join(sorted(missing)))


def contracts(env):
    packages = [
        "./" + str(p.relative_to(ROOT))
        for p in sorted((ROOT / "internal/control").glob("*/storage"))
    ]
    # Test fixtures truncate shared SQL tables. Serial package execution avoids
    # cross-package interference; concurrency inside each contract remains intact.
    args = [
        "go",
        "test",
        "-json",
        "-p=1",
        *packages,
        "./internal/app/control",
        "./internal/control/workflows",
        "./internal/control/identity/redis",
        "./internal/app/control/storage",
        "./internal/platform/events",
        "./internal/platform/redissecurity",
        "./migrations",
        "-run",
        "Integration|Postgres|Redis|Contract|AdvisoryLock",
        "-count=1",
        "-timeout=120s",
    ]
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        status = run(args, env, stdout=output)
        output.seek(0)
        if status:
            # Preserve Go's exit code even when its JSON is incomplete.
            for line in output:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("Output"):
                    print(event["Output"], end="")
            return status
        validate_events(output)
    print("SQL, Redis and migration integration tests passed without skips")
    return 0


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--external",
        action="store_true",
        help="authorize TEST_DATABASE_URL and TEST_REDIS_URL instead of isolated services",
    )
    args = parser.parse_args()
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    env = dict(os.environ)
    if args.external:
        for name, schemes in (
            ("TEST_DATABASE_URL", {"postgres", "postgresql"}),
            ("TEST_REDIS_URL", {"redis", "rediss"}),
        ):
            if not env.get(name):
                raise ValueError(f"{name} is required with --external")
            if urlsplit(env[name]).scheme not in schemes or not urlsplit(env[name]).hostname:
                raise ValueError(f"{name} must be a valid test service URL")
        require_commands("go")
        return contracts(env)
    postgres_port = port(env.get("INTEGRATION_POSTGRES_PORT", "55432"), "INTEGRATION_POSTGRES_PORT")
    redis_port = port(env.get("INTEGRATION_REDIS_PORT", "56379"), "INTEGRATION_REDIS_PORT")
    if postgres_port == redis_port:
        raise ValueError("Integration PostgreSQL and Redis ports must differ")
    require_commands("docker", "go")
    result = run(["docker", "info"], env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result:
        raise ValueError("Docker daemon unavailable; start Docker first")
    project = "homeharbor-integration-" + uuid.uuid4().hex[:12]
    compose = [
        "docker",
        "compose",
        "--project-name",
        project,
        "--file",
        str(ROOT / "deploy/compose.integration.yaml"),
    ]
    status = 0
    with tempfile.TemporaryDirectory(prefix=project + "-") as directory:
        env.update(
            INTEGRATION_SECRETS_DIR=directory,
            INTEGRATION_POSTGRES_PORT=str(postgres_port),
            INTEGRATION_REDIS_PORT=str(redis_port),
        )
        passwords = [base64.b64encode(secrets.token_bytes(32)).decode() for _ in range(2)]
        for name, password in zip(("postgres", "redis"), passwords, strict=True):
            path = Path(directory) / f"{name}_password"
            path.write_text(password)
            path.chmod(0o600)
        env.update(test_urls(*passwords, postgres_port, redis_port))
        try:
            status = run(
                [
                    *compose,
                    "up",
                    "--detach",
                    "--wait",
                    "--wait-timeout",
                    "120",
                    "postgres",
                    "redis",
                ],
                env,
            )
            if not status:
                status = contracts(env)
        finally:
            # Signals cannot interrupt cleanup halfway; the original exit status
            # or exception remains authoritative when teardown also fails.
            for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, signal.SIG_IGN)
            try:
                cleanup = subprocess.run(
                    [*compose, "down", "--volumes", "--remove-orphans"],
                    env=env,
                    capture_output=True,
                    timeout=60,
                    check=False,
                )
                if cleanup.returncode:
                    print(
                        f"Integration cleanup failed for project {project} (exit {cleanup.returncode})",
                        file=sys.stderr,
                    )
                    if not status:
                        status = cleanup.returncode
            except (OSError, subprocess.TimeoutExpired) as error:
                # Exception text/Compose stderr may include credential-bearing
                # environment values. Report the failure class, not its payload.
                print(
                    f"Integration cleanup failed for project {project} ({type(error).__name__})",
                    file=sys.stderr,
                )
                if not status:
                    status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(cli(main))
