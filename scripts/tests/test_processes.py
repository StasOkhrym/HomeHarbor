"""Exercise process ownership with real children, not mocked signal delivery."""

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ProcessOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="homeharbor-process-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.pid_file = self.directory / "child.pid"

    def running(self, pid):
        status = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False
        ).stdout.strip()
        return bool(status) and not status.startswith("Z")

    def cleanup_child(self):
        if self.pid_file.exists():
            try:
                os.kill(int(self.pid_file.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def wait_for_pid(self):
        deadline = time.monotonic() + 5
        while not self.pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.02)

        self.assertTrue(self.pid_file.exists(), "child never started")

        self.addCleanup(self.cleanup_child)
        return int(self.pid_file.read_text())

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 2
        while self.running(pid) and time.monotonic() < deadline:
            time.sleep(0.02)

        self.assertFalse(self.running(pid), "owned child survived runner shutdown")

    def finish(self, process):
        try:
            return process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.cleanup_child()
            process.kill()
            process.communicate(timeout=5)

            self.fail("owned descendant kept process pipes open after shutdown")

    def test_integration_external_signal_stops_child(self):
        helper = self.directory / "go"
        helper.write_text(
            f"#!{sys.executable}\nimport os, time\n"
            f"open({str(self.pid_file)!r}, 'w').write(str(os.getpid()))\ntime.sleep(90)\n"
        )
        helper.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{self.directory}:{os.environ['PATH']}",
            "TEST_DATABASE_URL": "postgres://test",
            "TEST_REDIS_URL": "redis://test",
            "PYTHONPATH": str(ROOT / "scripts"),
        }
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "from integration import main; raise SystemExit(main())",
                "--external",
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.kill if process.poll() is None else lambda: None)
        pid = self.wait_for_pid()
        process.send_signal(signal.SIGTERM)
        output, error = self.finish(process)

        self.assertEqual(process.returncode, 143, (output, error))
        self.assert_stopped(pid)

    def test_integration_signal_stops_surviving_grandchild(self):
        ready = self.directory / "ready"
        child_code = (
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"open({str(ready)!r}, 'w').close(); time.sleep(90)"
        )
        parent_code = (
            "import subprocess,sys,time; from pathlib import Path; "
            f"p=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            f"Path({str(self.pid_file)!r}).write_text(str(p.pid)); "
            f"ready=Path({str(ready)!r})\n"
            "while not ready.exists(): time.sleep(0.02)\n"
        )
        args = [sys.executable, "-c", parent_code]
        code = f"import os; from integration import run; raise SystemExit(run({args!r}, dict(os.environ)))"
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.kill if process.poll() is None else lambda: None)
        pid = self.wait_for_pid()
        output, error = self.finish(process)

        self.assertEqual(process.returncode, 0, (output, error))
        self.assert_stopped(pid)

    def test_signal_during_cleanup_still_stops_descendant(self):
        ready = self.directory / "ready"
        cleanup_started = self.directory / "cleanup-started"
        child_code = (
            "import signal,time; from pathlib import Path; "
            f"signal.signal(signal.SIGTERM, lambda *_: Path({str(cleanup_started)!r}).touch()); "
            f"Path({str(ready)!r}).touch(); time.sleep(90)"
        )
        parent_code = (
            "import subprocess,sys,time; from pathlib import Path; "
            f"p=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
            f"Path({str(self.pid_file)!r}).write_text(str(p.pid)); "
            f"ready=Path({str(ready)!r})\n"
            "while not ready.exists(): time.sleep(0.02)\n"
        )
        code = (
            "import os,signal; from integration import run,interrupted; "
            "signal.signal(signal.SIGTERM, interrupted); "
            f"raise SystemExit(run({[sys.executable, '-c', parent_code]!r}, dict(os.environ)))"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.kill if process.poll() is None else lambda: None)
        pid = self.wait_for_pid()
        deadline = time.monotonic() + 5
        while not cleanup_started.exists() and time.monotonic() < deadline:
            time.sleep(0.02)

        self.assertTrue(cleanup_started.exists(), "cleanup never started")

        process.send_signal(signal.SIGTERM)
        output, error = self.finish(process)

        self.assertEqual(process.returncode, 143, (output, error))
        self.assert_stopped(pid)

    def test_run_owns_signal_cleanup_without_global_main_handler(self):
        child_code = (
            "import os,time; from pathlib import Path; "
            f"Path({str(self.pid_file)!r}).write_text(str(os.getpid())); time.sleep(90)"
        )
        code = (
            "import os; from integration import run; "
            f"raise SystemExit(run({[sys.executable, '-c', child_code]!r}, dict(os.environ)))"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            env={**os.environ, "PYTHONPATH": str(ROOT / "scripts")},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(process.kill if process.poll() is None else lambda: None)
        pid = self.wait_for_pid()
        process.send_signal(signal.SIGTERM)
        output, error = self.finish(process)

        self.assertEqual(process.returncode, 143, (output, error))
        self.assert_stopped(pid)
