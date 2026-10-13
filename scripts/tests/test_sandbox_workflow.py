"""Opt-in workflow contracts. Fake Docker boundary; no host networking effects."""

import contextlib
import importlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))


class DockerBoundary:
    def __init__(self):
        self.resources = {"container": [], "network": [], "volume": []}
        self.calls = []
        self.failure = False
        self.name_only = {"container": [], "network": [], "volume": []}

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failure:
            raise ValueError("Docker failed (private-token-sentinel)")
        if args[0].endswith("/bin/client"):
            result = subprocess.run(args, capture_output=True, text=True, check=True)
            return result.stdout
        if args[1:3] == ["ps", "--all"]:
            items = (
                self.name_only["container"]
                if any(a.startswith("name=") for a in args)
                else self.resources["container"]
            )
            return "\n".join(item["Id"] for item in items)
        if args[1] in {"network", "volume"} and args[2] == "ls":
            items = (
                self.name_only[args[1]]
                if any(a.startswith("name=") for a in args)
                else self.resources[args[1]]
            )
            return "\n".join(item.get("Id", item.get("Name")) for item in items)
        if "inspect" in args:
            kind = "container" if args[1] == "inspect" else args[1]
            return json.dumps([*self.resources[kind], *self.name_only[kind]])

        return ""


class SandboxWorkflowTests(unittest.TestCase):
    def workflow(self, directory, docker=None):
        try:
            module = importlib.import_module("sandbox_workflow")
        except ModuleNotFoundError:
            self.fail("optional sandbox workflow is not implemented")

        return module.Workflow(Path(directory), run=docker or DockerBoundary(), uid=501)

    def owned(self, directory, docker=None):
        flow = self.workflow(directory, docker)
        flow.create_owner()
        return flow

    def resource(self, flow, kind, name="owned", running=False):
        labels = {
            "com.docker.compose.project": "homeharbor-sandbox",
            "io.homeharbor.sandbox.workspace": str(flow.root),
            "io.homeharbor.sandbox.owner": "501",
        }
        if kind == "container":
            return {"Id": name, "Config": {"Labels": labels}, "State": {"Running": running}}

        return {"Id": name, "Name": name, "Labels": labels}

    def test_down_preserves_state(self):
        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = self.owned(temp, docker)
            state = flow.sandbox / "client.json"
            state.write_bytes(b"private-identity-sentinel")
            docker.resources["volume"] = [self.resource(flow, "volume")]
            flow.down()

            self.assertEqual(state.read_bytes(), b"private-identity-sentinel")
            self.assertTrue(flow.owner_file.is_file())

            mutations = [args for args, _ in docker.calls if "down" in args]

            self.assertEqual(len(mutations), 1)
            self.assertNotIn("--volumes", mutations[0])

    def test_reset_rejects_active_or_foreign_project(self):
        for kind in ("container", "network", "volume"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                docker = DockerBoundary()
                flow = self.owned(temp, docker)
                item = self.resource(flow, kind)
                labels = item["Config"]["Labels"] if kind == "container" else item["Labels"]
                labels["io.homeharbor.sandbox.workspace"] = "/other-checkout"
                docker.resources[kind] = [item]

                with self.assertRaisesRegex(ValueError, "foreign|ownership"):
                    flow.reset()

                self.assertTrue(flow.owner_file.is_file())
                self.assertFalse(any("down" in args for args, _ in docker.calls))

        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = self.owned(temp, docker)
            docker.resources["container"] = [self.resource(flow, "container", running=True)]

            with self.assertRaisesRegex(ValueError, "running|active"):
                flow.reset()

            self.assertTrue(flow.owner_file.is_file())

    def test_reset_archives_only_owned_stopped_state_inside_ignored_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = self.owned(temp, docker)
            state = flow.sandbox / "root-key.age"
            state.write_bytes(b"secret-sentinel")
            other = flow.root / ".local"
            other.mkdir()
            (other / "keep").write_text("dev-state")
            flow.reset()

            self.assertFalse(state.exists())
            self.assertEqual((other / "keep").read_text(), "dev-state")

            archives = list((flow.sandbox / "archives").glob("*/root-key.age"))

            self.assertEqual(len(archives), 1)
            self.assertEqual(archives[0].read_bytes(), b"secret-sentinel")
            self.assertIn("--volumes", next(args for args, _ in docker.calls if "down" in args))

    def test_cleanup_requires_ownership(self):
        for operation in ("down", "reset"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temp:
                docker = DockerBoundary()
                flow = self.workflow(temp, docker)
                flow.sandbox.mkdir()
                (flow.sandbox / "client.json").write_text("private")

                with self.assertRaisesRegex(ValueError, "ownership|owner|unowned"):
                    getattr(flow, operation)()

                self.assertEqual(docker.calls, [])

        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            value = json.loads(flow.owner_file.read_text())
            value["workspace"] = "/somewhere-else"
            flow.owner_file.write_text(json.dumps(value))

            with self.assertRaisesRegex(ValueError, "ownership|owner"):
                flow.down()

    def test_symlink_lock_or_state_cannot_change_foreign_files(self):
        for name in ("workflow.lock", "workflow-owner.json", "client.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                docker = DockerBoundary()
                flow = self.owned(temp, docker)
                outside = flow.root / "foreign"
                outside.write_text("keep")
                target = flow.sandbox / name
                target.unlink(missing_ok=True)
                target.symlink_to(outside)

                with self.assertRaisesRegex(ValueError, "symlink|regular|ownership"):
                    flow.reset()

                self.assertEqual(outside.read_text(), "keep")
                self.assertFalse(any("down" in args for args, _ in docker.calls))

    def test_existing_unlabeled_volume_prevents_owner_creation(self):
        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            docker.resources["volume"] = [{"Name": "legacy", "Labels": {}}]
            flow = self.workflow(temp, docker)

            with self.assertRaisesRegex(ValueError, "foreign|ownership"):
                flow.create_owner()

            self.assertFalse(flow.owner_file.exists())

    def test_up_refuses_non_macos_before_any_provisioning(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.workflow(temp)

            with patch("sandbox_workflow.sys.platform", "linux"):
                with self.assertRaisesRegex(ValueError, "macOS"):
                    flow.up()

            self.assertFalse(flow.sandbox.exists())
            self.assertEqual(flow.run.calls, [])

    def test_named_unlabeled_resources_cannot_be_adopted_or_deleted(self):
        for kind in ("container", "network", "volume"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                docker = DockerBoundary()
                flow = self.owned(temp, docker)
                item = self.resource(flow, kind)
                item["Config" if kind == "container" else "Labels"] = {}
                docker.name_only[kind] = [item]

                with self.assertRaisesRegex(ValueError, "foreign|ownership"):
                    flow.down()

                self.assertFalse(any("down" in args for args, _ in docker.calls))

    def test_docker_selection_is_pinned_and_ambient_overrides_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = self.owned(temp, docker)
            flow.down()
            args, kwargs = next((a, k) for a, k in docker.calls if "down" in a)

            self.assertEqual(
                args[:4], ["docker", "compose", "--project-name", "homeharbor-sandbox"]
            )
            self.assertIn(str(flow.root / "deploy/compose.sandbox.yaml"), args)
            self.assertIn("--env-file", args)
            self.assertEqual(kwargs["env"]["SANDBOX_WORKSPACE"], str(flow.root))
            self.assertEqual(kwargs["env"]["RUNTIME_UID"], "501")

    def test_production_config_environment_cannot_override_isolated_sandbox(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.workflow(temp)
            inherited = {
                "HOMEHARBOR_NODE_CONTROL_URL": "https://production.example",
                "HOMEHARBOR_COORDINATION_ROOT_PUBLIC_KEY_FILE": "/production/root.pub",
                "HOMEHARBOR_RUNTIME_SHUTDOWN_TIMEOUT": "1s",
                "COMPOSE_PROJECT_NAME": "production",
            }

            with patch.dict(os.environ, inherited):
                env = flow.environment()

            for key in inherited:
                self.assertFalse(key in env, f"inherited sandbox override retained: {key}")

            self.assertEqual(env["SANDBOX_WORKSPACE"], str(flow.root))
            self.assertEqual(env["RUNTIME_UID"], "501")

    def test_commands_do_not_log_invite_code(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            # The command boundary can contain credentials in stderr; the workflow
            # must never copy that output or the captured exception into its error.
            flow.run.failure = True
            output = io.StringIO()

            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                with self.assertRaises(ValueError) as error:
                    flow.status()

            self.assertNotIn("private-token-sentinel", str(error.exception) + output.getvalue())

    def test_failed_command_preserves_exit_code_without_captured_private_output(self):
        from sandbox_workflow import quiet_command

        with tempfile.TemporaryDirectory() as temp:
            flow = self.workflow(temp, quiet_command)

            with self.assertRaises(ValueError) as error:
                flow.command(
                    [sys.executable, "-c", "import sys; print('private-code'); sys.exit(7)"]
                )

            self.assertEqual(getattr(error.exception, "code", None), 7)
            self.assertNotIn("private-code", str(error.exception))

    def test_network_cleanup_failure_preserves_docker_and_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            docker = DockerBoundary()
            flow = self.owned(temp, docker)
            (flow.sandbox / "native-dirty").write_text("1\n")
            (flow.sandbox / "client.json").write_text("private")

            # A missing native config/helper must block Docker teardown/reset.
            with self.assertRaisesRegex(ValueError, "native|cleanup|config"):
                flow.down()

            self.assertEqual((flow.sandbox / "client.json").read_text(), "private")
            self.assertFalse(any("down" in args for args, _ in docker.calls))

    def test_sandbox_excluded_from_every_required_gate(self):
        targets = ("up", "client", "status", "logs", "check", "down", "reset")
        makefile = (ROOT / "Makefile").read_text()
        for target in targets:
            self.assertIn(f"sandbox-{target}", makefile)
        files = [
            ROOT / "scripts/verify.sh",
            ROOT / "scripts/integration.py",
            ROOT / "scripts/acceptance.sh",
        ]
        files.extend((ROOT / ".github").rglob("*.yml"))
        for path in files:
            text = path.read_text()
            self.assertNotIn("scripts/sandbox.sh", text, str(path))
            self.assertNotIn("sandbox_workflow.py", text, str(path))
            for target in targets:
                self.assertNotIn(f"make sandbox-{target}", text, str(path))
        # Required target recipes must not depend on or launch sandbox orchestration.
        for name in ("verify", "test", "lint", "integration", "acceptance", "security"):
            recipe = makefile.split(f"\n{name}:", 1)[1].split("\n\n", 1)[0]
            self.assertNotIn("sandbox-", recipe)
            self.assertNotIn("sandbox.sh", recipe)

    def test_all_compose_resources_have_owner_labels(self):
        config = yaml.safe_load((ROOT / "deploy/compose.sandbox.yaml").read_text())
        for kind in ("services", "networks", "volumes"):
            for name, value in config[kind].items():
                with self.subTest(kind=kind, name=name):
                    self.assertIn(
                        "io.homeharbor.sandbox.workspace", (value or {}).get("labels", {})
                    )
                    self.assertIn("io.homeharbor.sandbox.owner", (value or {}).get("labels", {}))

    def test_non_profile_probe_has_real_unpublished_listener(self):
        config = yaml.safe_load((ROOT / "deploy/compose.sandbox.yaml").read_text())
        site = config["services"]["site"]
        self.assertIn("8081", " ".join(site["command"]))
        self.assertNotIn("ports", site)
        self.assertNotIn("8081", (ROOT / "deploy/sandbox/initial-snapshot.toml").read_text())

    def test_logs_project_only_public_events_without_free_text(self):
        try:
            from sandbox_diagnostics import public_log_lines
        except ModuleNotFoundError:
            self.fail("public-only sandbox log projection is missing")

        raw = "\n".join(
            (
                'control-1 | {"level":"info","event":"snapshot.applied","revision":3,"msg":"secret-code"}',
                "relay-1 | invite=secret-code token=private-token",
                'control-1 | {"event":"invite.created","code":"secret-code"}',
                'gateway-1 | {"level":"error","msg":"secret-code"}',
            )
        )
        lines = public_log_lines(raw)

        self.assertTrue(any("snapshot.applied" in line and "3" in line for line in lines))
        self.assertNotIn("secret-code", "\n".join(lines))
        self.assertNotIn("private-token", "\n".join(lines))

    def test_actual_slog_messages_are_projected_without_paths_or_free_text(self):
        from sandbox_diagnostics import public_log_lines

        lines = public_log_lines(
            "\n".join(
                (
                    'control-1 | {"level":"INFO","msg":"control listening","address":"secret-sentinel"}',
                    'control-1 | {"level":"INFO","msg":"http request","status":200,"method":"POST","path":"/invite/secret-sentinel"}',
                    'relay-1 | {"level":"INFO","msg":"relay starting","address":"secret-sentinel"}',
                )
            )
        )

        self.assertTrue(any("control.listening" in line for line in lines))
        self.assertTrue(any("http.request" in line and "200" in line for line in lines))
        self.assertTrue(any("relay.starting" in line for line in lines))
        self.assertNotIn("secret-sentinel", "\n".join(lines))

    def test_malformed_log_fields_cannot_leak_or_break_public_projection(self):
        from sandbox_diagnostics import public_log_lines

        lines = public_log_lines(
            "\n".join(
                (
                    '{"msg":{"private":"secret"},"event":"snapshot.applied","revision":3,"method":[]}',
                    '{"event":"relay.secret","level":[]}',
                    "[]",
                    "malformed secret",
                )
            )
        )

        self.assertTrue(any("snapshot.applied" in line for line in lines))
        self.assertNotIn("secret", "\n".join(lines))

    def test_installed_native_binding_requires_cleanup_even_without_phase_marker(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            installed = flow.root / "installed-policy"
            installed.write_text("public")

            with patch("sandbox_workflow.SYSTEM_POLICY", installed):
                with self.assertRaisesRegex(ValueError, "native cleanup"):
                    flow.down()

            self.assertFalse(any("down" in args for args, _ in flow.run.calls))

    def test_non_profile_diagnostic_requires_listener_and_expected_state(self):
        from sandbox_diagnostics import check
        from sandbox_preflight import PROFILES, save_profile

        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            save_profile(PROFILES[1], flow.sandbox / "network.env")
            with patch("sandbox_diagnostics.probe", side_effect=(True, True, False)):
                self.assertEqual(check(flow, "allowed"), 0)
            with patch("sandbox_diagnostics.probe", side_effect=(False, False, False)):
                with self.assertRaisesRegex(ValueError, "differ"):
                    check(flow, "allowed")
            with patch("sandbox_diagnostics.probe", side_effect=(True, True, True)):
                with self.assertRaisesRegex(ValueError, "differ"):
                    check(flow, "allowed")
            flow.run.failure = True
            with patch("sandbox_diagnostics.probe") as probe:
                with self.assertRaises(ValueError):
                    check(flow, "denied")
                probe.assert_not_called()

    def test_down_stops_only_registered_foreground_client_and_recovers(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            binary = flow.sandbox / "bin/client"
            binary.parent.mkdir()
            ready = flow.sandbox / "test-ready"
            recovered = flow.sandbox / "test-recovered"
            binary.write_text(
                f"#!{sys.executable}\nimport pathlib,sys,time\n"
                f"root=pathlib.Path({str(flow.sandbox)!r})\n"
                "if 'network-close' in sys.argv:\n"
                " (root/'test-recovered').write_text('closed')\n"
                "else:\n"
                " (root/'test-ready').write_text('running')\n"
                " time.sleep(90)\n"
            )
            binary.chmod(0o700)
            (flow.sandbox / "native-client.toml").write_text("fixture: never applied")
            code = (
                "from sandbox_workflow import Workflow; from sandbox_runtime import run_client; "
                "from scripts.tests.test_sandbox_workflow import DockerBoundary; "
                f"run_client(Workflow(__import__('pathlib').Path({temp!r}),uid=501,run=DockerBoundary()))"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(ROOT / "scripts"), str(ROOT))),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)

                if not ready.exists() and process.poll() is not None:
                    output, error = process.communicate(timeout=5)

                    self.fail(f"registered native launcher failed: {output!r} {error!r}")

                self.assertTrue(ready.exists(), "registered native launcher never started")

                flow.down()
                output, error = process.communicate(timeout=5)

                self.assertEqual(process.returncode, 0, (output, error))
                self.assertEqual(recovered.read_text(), "closed")
                self.assertFalse((flow.sandbox / "native-dirty").exists())
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)

                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5)
                else:
                    process.communicate(timeout=5)

    def test_crashed_launcher_cannot_abandon_lock_or_signal_unregistered_child(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            binary = flow.sandbox / "bin/client"
            binary.parent.mkdir()
            child_pid = flow.sandbox / "test-child-pid"
            binary.write_text(
                f"#!{sys.executable}\nimport os,pathlib,time\n"
                f"pathlib.Path({str(child_pid)!r}).write_text(str(os.getpid()))\n"
                "time.sleep(90)\n"
            )
            binary.chmod(0o700)
            (flow.sandbox / "native-client.toml").write_text("test: no networking")
            code = (
                "from sandbox_workflow import Workflow; from sandbox_runtime import run_client; "
                "from scripts.tests.test_sandbox_workflow import DockerBoundary; "
                f'run_client(Workflow(__import__("pathlib").Path({temp!r}),uid=501,run=DockerBoundary()))'
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(ROOT / "scripts"), str(ROOT))),
                },
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            pid = None

            try:
                deadline = time.monotonic() + 5
                while (
                    not child_pid.exists()
                    and process.poll() is None
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)

                if not child_pid.exists():
                    process.kill()
                    output, error = process.communicate(timeout=5)

                    self.fail(f"owner did not start: {output!r} {error!r}")

                pid = int(child_pid.read_text())
                process.kill()
                process.wait(timeout=5)

                with self.assertRaisesRegex(ValueError, "active native client"):
                    flow.down()

                self.assertTrue((flow.sandbox / "native-dirty").exists())
                self.assertFalse(any("down" in args for args, _ in flow.run.calls))

                os.kill(pid, 0)  # scoped cleanup did not signal the still-live child
            finally:
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass

                if process.poll() is None:
                    process.kill()

                process.communicate(timeout=5)

    def test_signal_during_pending_join_stops_owned_child_without_public_export(self):
        with tempfile.TemporaryDirectory() as temp:
            flow = self.owned(temp)
            binary = flow.sandbox / "bin/client"
            binary.parent.mkdir()
            pid_file = flow.sandbox / "test-join-pid"
            binary.write_text(
                f"#!{sys.executable}\nimport os,pathlib,time\n"
                f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))\n"
                "time.sleep(90)\n"
            )
            binary.chmod(0o700)
            (flow.sandbox / "root-public.key").write_text("test-root")
            (flow.sandbox / "secrets").mkdir()
            (flow.sandbox / "secrets/relay_tls_ca").write_text("test-ca")
            code = (
                "from sandbox_workflow import Workflow; from sandbox_runtime import join; "
                "from scripts.tests.test_sandbox_workflow import DockerBoundary; "
                f'raise SystemExit(join(Workflow(__import__("pathlib").Path({temp!r}),uid=501,run=DockerBoundary())))'
            )
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join((str(ROOT / "scripts"), str(ROOT))),
                },
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            pid = None
            try:
                process.stdin.write(b"a" * 64 + b"\n")
                process.stdin.flush()
                deadline = time.monotonic() + 5
                while (
                    not pid_file.exists() and process.poll() is None and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                self.assertTrue(pid_file.exists(), "join did not start its child")
                pid = int(pid_file.read_text())
                process.terminate()
                # A surviving child retains the output pipes; don't let communicate
                # hide that condition behind a long timeout.
                process.wait(timeout=8)
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    state = subprocess.run(
                        ["ps", "-o", "stat=", "-p", str(pid)],
                        capture_output=True,
                        text=True,
                        check=False,
                    ).stdout.strip()
                    if not state or state.startswith("Z"):
                        break
                    time.sleep(0.02)
                self.assertFalse(
                    state and not state.startswith("Z"), "owned pending join survived its launcher"
                )
                self.assertFalse((flow.sandbox / "client-public.json").exists())
                self.assertEqual(process.returncode, 143)
            finally:
                if pid is not None:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
