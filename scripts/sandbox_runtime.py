"""Native foreground process owner and finite sandbox onboarding adapters."""

import base64
import contextlib
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import time

from process_owner import run as run_foreground
from sandbox_identity import read_public_file, unique_fields, validate_public_identity
from tooling import atomic_write

# The Go node accepts a process drain up to 60 seconds. Keep the outer owner
# alive through that deadline and a separate bounded offline helper recovery.
CLIENT_DRAIN_TIMEOUT = 65
CLIENT_STOP_TIMEOUT = 115


def socket_path(flow):
    path = flow.sandbox / "client.sock"
    flow.check_path(path.parent)
    if len(os.fsencode(path)) > 103:
        raise ValueError("sandbox checkout path is too long for its private client control socket")

    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("foreign client control socket; refusing operation")

    return path


def stop_client(flow):
    try:
        with flow.lock("client-runtime.lock"):
            path = socket_path(flow)
            path.unlink(missing_ok=True)
            return
    except ValueError as error:
        if "active" not in str(error):
            raise

    path = socket_path(flow)

    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(path))
            connection.sendall(b"stop\n")
            if connection.recv(16) != b"stopping\n":
                raise ValueError("native client refused its scoped stop request")
    except OSError:
        raise ValueError(
            "active native client has no reachable owner; stop its original terminal before recovery"
        ) from None

    deadline = time.monotonic() + CLIENT_STOP_TIMEOUT
    while True:
        try:
            with flow.lock("client-runtime.lock"):
                return
        except ValueError as error:
            if "active" not in str(error) or time.monotonic() >= deadline:
                raise ValueError(
                    "native client has not stopped; identity and Docker state preserved"
                ) from None

        time.sleep(0.1)


def require_file(flow, name):
    path = flow.sandbox / name
    flow.check_path(path)
    if not path.is_file():
        raise ValueError(f"sandbox requires existing {name}")

    return path


def build_client(flow):
    binary = flow.sandbox / "bin/client"
    flow.check_path(binary)
    binary.parent.mkdir(mode=0o700, exist_ok=True)
    flow.command(
        ["go", "build", "-trimpath", "-o", str(binary), "./cmd/client"],
        env=flow.environment(),
        timeout=300,
    )
    binary.chmod(0o700)
    return binary


def run_client(flow):
    """The owner socket signals the live child object, never a saved/reusable PID."""

    process = None
    pending_signal = None
    stopped_by_owner = False
    handlers = {}

    def interrupted(signum, _frame):
        nonlocal pending_signal
        if pending_signal is None:
            pending_signal = signum

    with contextlib.ExitStack() as lifetime:
        with flow.lock():
            flow.require_owner()
            flow.inventory()
            runtime_fd = lifetime.enter_context(flow.lock("client-runtime.lock"))
            binary = require_file(flow, "bin/client")
            config = require_file(flow, "native-client.toml")
            path = socket_path(flow)
            path.unlink(missing_ok=True)  # only after owning the exclusive runtime lock
            server = lifetime.enter_context(socket.socket(socket.AF_UNIX))
            server.bind(str(path))
            path.chmod(0o600)
            socket_info = path.lstat()

            def remove_socket():
                if path.exists():
                    current = path.lstat()
                    if (current.st_dev, current.st_ino) == (socket_info.st_dev, socket_info.st_ino):
                        path.unlink()

            lifetime.callback(remove_socket)
            server.listen(1)
            server.settimeout(0.1)
            dirty = flow.sandbox / "native-dirty"
            flow.check_path(dirty)
            # Persist intent before the child can invoke any privileged apply.
            atomic_write(dirty, b"1\n")
            for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                handlers[sig] = signal.signal(sig, interrupted)

            try:
                process = subprocess.Popen(
                    [str(binary), "--config", str(config)],
                    env=flow.environment(),
                    start_new_session=True,
                    pass_fds=(runtime_fd,),
                )
            except BaseException:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)

                raise

        # Release the orchestration lock while retaining the process lifetime lock.
        # This lets sandbox-down request a graceful stop without a PID registry.
        try:
            while process.poll() is None and pending_signal is None and not stopped_by_owner:
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    continue

                with connection:
                    connection.settimeout(1)

                    try:
                        if connection.recv(16) == b"stop\n":
                            stopped_by_owner = True
                            connection.sendall(b"stopping\n")
                    except OSError:
                        continue

            if process.poll() is None:
                process.terminate()

                try:
                    process.wait(timeout=CLIENT_DRAIN_TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise ValueError(
                        "native client drain timed out; run sandbox-down for journal recovery"
                    ) from None

            flow.cleanup_native()
            if pending_signal is not None:
                return 128 + pending_signal
            if stopped_by_owner:
                return 0

            return process.returncode
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

            for sig, handler in handlers.items():
                signal.signal(sig, handler)


def save_public(flow, filename, output):
    try:
        public = validate_public_identity(json.loads(output, object_pairs_hook=unique_fields))
    except (ValueError, TypeError):
        raise ValueError(
            "node did not emit a valid public identity; private output withheld"
        ) from None

    path = flow.sandbox / filename
    flow.check_path(path)
    previous = read_public_file(path)
    if previous is not None and json.loads(previous) != public:
        raise ValueError("public identity changed; explicit cleanup/reset is required")

    atomic_write(path, (json.dumps(public, sort_keys=True) + "\n").encode())


def join(flow, trust_fingerprint=None):
    with flow.lock():
        flow.require_owner()
        flow.inventory()
        # The public fingerprint comes from the operator, never from an implicit
        # computation over the same local root file. Keep private pipe input
        # entirely with the production Go command; Python readline can prefetch it.
        fingerprint = trust_fingerprint
        if fingerprint is None:
            fingerprint = os.environ.get("SANDBOX_TRUST_FINGERPRINT") or None

        if fingerprint is None:
            if not sys.stdin.isatty():
                raise ValueError("piped join requires an independently trusted --trust-fingerprint")

            fingerprint = input("Trusted out-of-band root/network fingerprint: ")

        fingerprint = fingerprint.strip()
        if len(fingerprint) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in fingerprint
        ):
            raise ValueError("trusted fingerprint must be a SHA-256 hex digest")

        root = require_file(flow, "root-public.key")
        ca = require_file(flow, "secrets/relay_tls_ca")
        state = flow.sandbox / "client.json"
        flow.check_path(state)
        binary = build_client(flow)
        control = (
            f"https://control.localhost:{flow.environment().get('SANDBOX_HTTPS_PORT', '8443')}"
        )
        result = run_foreground(
            [
                str(binary),
                "join",
                "--control",
                control,
                "--ca-file",
                str(ca),
                "--root-public-key",
                str(root),
                "--network-id",
                "sandbox-network",
                "--trust-fingerprint",
                fingerprint,
                "--state",
                str(state),
            ],
            env=flow.environment(),
        )
        if result:
            return result

        public = flow.command([str(binary), "identity", "--state", str(state)], timeout=30)
        save_public(flow, "client-public.json", public)

    print("Client credential claimed. No native networking applied; next: sandbox-prepare.")
    return 0


def gateway(flow, action):
    if action not in {"enroll", "run"}:
        raise ValueError("gateway action must be enroll or run")

    with flow.lock():
        flow.require_owner()
        resources = flow.inventory()
        if action == "run":
            require_file(flow, "network-helper.json")
            flow.compose("up", "--detach", "--no-deps", "gateway")
            print(
                "Gateway started. Signed authorization and tunnel reachability still require checks."
            )
            return 0
        if any(
            item.get("Config", {}).get("Labels", {}).get("com.docker.compose.service") == "gateway"
            and item.get("State", {}).get("Running")
            for item in resources["container"]
        ):
            raise ValueError("stop the gateway runtime before enrollment/public export")

        if sys.stdin.isatty():
            import getpass

            token = getpass.getpass("Gateway-role enrollment token (hidden): ")
        else:
            token = sys.stdin.readline(4097).rstrip("\r\n")

        if not token or len(token) > 4096 or any(char.isspace() for char in token):
            raise ValueError("gateway enrollment token is missing or invalid")

        public = flow.compose(
            "run",
            "--rm",
            "--no-deps",
            "-T",
            "gateway",
            "enroll",
            "--control",
            "https://control.sandbox:8443",
            "--ca-file",
            "/run/secrets/relay_tls_ca",
            "--state",
            "/var/lib/homeharbor/gateway.json",
            "--name",
            "Sandbox gateway",
            input=token + "\n",
            timeout=90,
        )
        save_public(flow, "gateway-public.json", public)
        flow.script("sandbox_bind.py")

    print("Gateway enrolled and public manifest bound. Companion signing is still required.")
    return 0


def fingerprint(flow):
    raw = require_file(flow, "root-public.key").read_bytes().strip()

    try:
        key = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except ValueError:
        raise ValueError("sandbox public root is malformed") from None

    if len(key) != 32:
        raise ValueError("sandbox public root must contain an Ed25519 key")

    return hashlib.sha256(b"homeharbor/network-trust/v1\0" + key + b"sandbox-network").hexdigest()


def dispatch(flow, command, action, trust_fingerprint=None):
    if command == "client":
        if action == "join":
            return join(flow, trust_fingerprint)
        if action in {None, "run"}:
            return run_client(flow)
        if action == "close":
            flow.down()
            return 0

        raise ValueError("client action must be join, run or close")
    if command == "gateway":
        return gateway(flow, action)
    if command == "prepare":
        if action not in {None, "fingerprint"}:
            raise ValueError("prepare accepts only the optional fingerprint action")

        with flow.lock():
            flow.require_owner()
            flow.inventory()
            if action == "fingerprint":
                print(fingerprint(flow))
                return 0

            flow.script("sandbox_prepare.py")

        print("Public helper policy candidate ready; explicit root-owned provisioning is required.")
        return 0
    if command == "check":
        from sandbox_diagnostics import check

        return check(flow, action)

    raise ValueError("unknown sandbox action")
