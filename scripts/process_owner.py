"""Own a foreground subprocess session across cancellation and cleanup."""

import os
import signal
import subprocess
import sys
import time


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
