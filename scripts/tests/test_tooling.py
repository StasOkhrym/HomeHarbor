"""Run real entrypoints in disposable repositories; fake only external CLIs."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="homeharbor-tooling-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        shutil.copytree(ROOT / "config", self.root / "config")
        shutil.copytree(ROOT / "deploy", self.root / "deploy")
        shutil.copy(ROOT / "Makefile", self.root / "Makefile")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # The harness requires Python 3.11+, not Apple's unrelated system 3.9.
        (self.bin / "python3").write_text('#!/bin/sh\nexec "' + sys.executable + '" "$@"\n')
        (self.bin / "python3").chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin"}
        # Fixtures own their fake interpreter and Make invocation. An inherited
        # command-line override in MAKEFLAGS can bypass a cleared PYTHON value.
        for key in (
            "PYTHON",
            "MAKEFLAGS",
            "MFLAGS",
            "GNUMAKEFLAGS",
            "MAKEOVERRIDES",
            "MAKEFILES",
            "MAKELEVEL",
        ):
            self.env.pop(key, None)

        for key in (
            "FULL",
            "TEST_DATABASE_URL",
            "TEST_REDIS_URL",
            "INTEGRATION_POSTGRES_PORT",
            "INTEGRATION_REDIS_PORT",
            "CONTROL_DOMAIN",
            "RELAY_DOMAIN",
            "DEV_HTTPS_PORT",
            "PROXY_HTTP_PORT",
        ):
            self.env.pop(key, None)

    def cli(self, name, body="exit 0\n"):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def run_script(self, name, *args):
        python_scripts = {
            "dev-init": "dev_init",
            "compose-check": "compose_check",
            "integration": "integration",
            "integration-local": "integration",
        }
        command = (
            [sys.executable, f"scripts/{python_scripts[name]}.py"]
            if name in python_scripts
            else ["/bin/sh", f"scripts/{name}.sh"]
        )
        if name == "integration":
            command.append("--external")
        return subprocess.run(
            [*command, *args], cwd=self.root, env=self.env, capture_output=True, text=True
        )

    def dependencies(self):
        for name in (
            "go",
            "git",
            "golangci-lint",
            "node",
            "npm",
            "ruff",
            "djlint",
            "shellcheck",
            "yamllint",
            "sqlfluff",
            "hadolint",
        ):
            self.cli(name)

    def integration_events(
        self,
        *,
        skip=False,
        missing_redis=False,
        missing_sessions=False,
        missing_recovery=False,
        missing_coordination=False,
    ):
        events = [
            {
                "Action": "pass",
                "Package": "example/internal/control/devices/storage",
                "Test": "TestPostgresEnrollment",
            },
            {
                "Action": "pass",
                "Package": "example/migrations",
                "Test": "TestConcurrentUpSerializesWithAdvisoryLock",
            },
        ]
        for module in (
            "audit",
            "identity",
            "invites",
            "policy",
            "profiles",
            "routes",
            "services",
            "snapshots",
        ):
            events.append(
                {
                    "Action": "pass",
                    "Package": f"example/internal/control/{module}/storage",
                    "Test": "TestPostgresContract",
                }
            )
        events.append(
            {
                "Action": "pass",
                "Package": "example/internal/control/transactions",
                "Test": "TestPostgresActivation",
            }
        )
        if not missing_redis:
            events.append(
                {
                    "Action": "skip" if skip else "pass",
                    "Package": "example/internal/platform/redissecurity",
                    "Test": "TestRedisChallenge",
                }
            )
        if not missing_recovery:
            events.extend(
                [
                    {
                        "Action": "pass",
                        "Package": "example/internal/control/workflows",
                        "Test": "TestRedisRecoveryChallengeConsumedOnceAcrossReplicas",
                    },
                    {
                        "Action": "pass",
                        "Package": "example/internal/control/devices/storage",
                        "Test": "TestPostgresRecoveredCredentialInvalidatesOldCredential",
                    },
                ]
            )
        if not missing_coordination:
            events.append(
                {
                    "Action": "pass",
                    "Package": "example/internal/control/coordination",
                    "Test": "TestPostgresCoordinationCrossReplicaRevoke",
                }
            )
        if not missing_sessions:
            events.append(
                {
                    "Action": "pass",
                    "Package": "example/internal/control/identity/redis",
                    "Test": "TestRedisSessionSharedTTLAndRevoke",
                }
            )
        self.cli(
            "go",
            '[ "$1" = test ] || exit 99\n[ "$2" = -json ] || exit 98\n'
            + "printf '%s\\n' \"$*\" >> integration-go.log\n"
            + "printf '%s\\n' '"
            + "\n".join(json.dumps(e) for e in events)
            + "'\n",
        )
        self.env.update(TEST_DATABASE_URL="postgres://test", TEST_REDIS_URL="redis://test")

    def test_backend_doctor_does_not_require_xcode_or_docker(self):
        self.dependencies()
        result = self.run_script("doctor", "backend")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_doctor_is_backend(self):
        self.dependencies()
        result = self.run_script("doctor")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("xcodebuild", result.stdout + result.stderr)

    def test_mobile_doctor_is_outside_backend_scope(self):
        result = self.run_script("doctor", "ios")

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("xcodebuild", result.stdout + result.stderr)

    def test_e2e_doctor_requires_linux_vm_tools(self):
        self.cli("uname", "printf Darwin\n")
        self.dependencies()
        self.cli("docker")
        result = self.run_script("doctor", "e2e")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("limactl", result.stderr)

    def test_integration_requires_redis_before_running_go(self):
        self.cli("go", "exit 99\n")
        self.env["TEST_DATABASE_URL"] = "postgres://test"
        result = self.run_script("integration")

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("TEST_REDIS_URL", result.stderr)

    def test_integration_rejects_skipped_redis(self):
        self.integration_events(skip=True)
        result = self.run_script("integration")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("skip", result.stderr.lower())

    def test_integration_rejects_absent_redis_tests(self):
        self.integration_events(missing_redis=True)
        result = self.run_script("integration")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Redis", result.stderr)

    def test_integration_accepts_executed_sql_redis_and_migrations(self):
        self.integration_events()
        result = self.run_script("integration")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_integration_requires_browser_session_contract(self):
        self.integration_events(missing_sessions=True)
        result = self.run_script("integration")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("browser sessions", result.stderr)

    def test_integration_requires_recovery_contracts(self):
        self.integration_events(missing_recovery=True)
        result = self.run_script("integration")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("credential recovery", result.stderr)

    def test_integration_requires_coordination_cross_replica_revoke(self):
        self.integration_events(missing_coordination=True)
        result = self.run_script("integration")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coordination cross-replica revoke", result.stderr)
        self.assertIn(
            "./internal/control/coordination", (self.root / "integration-go.log").read_text()
        )

    def test_integration_propagates_go_failure(self):
        self.integration_events()
        self.cli("go", "exit 17\n")
        result = self.run_script("integration")

        self.assertEqual(result.returncode, 17, result.stderr)

    def local_state(self):
        local = self.root / ".local"
        local.mkdir()
        for name in ("root-key.age", "root-public.key", "root-passphrase"):
            (local / name).write_text(f"existing-{name}")

        secrets = self.root / "secrets"
        secrets.mkdir()
        for name, length in (
            ("postgres_password", 44),
            ("redis_password", 44),
            ("relay_ticket_key", 44),
            ("session_signing_key", 64),
            ("ceremony_encryption_key", 32),
        ):
            (secrets / name).write_text("A" * length)
            (secrets / name).chmod(0o600)

        return local, secrets

    def test_local_restart_preserves_existing_state(self):
        local, secrets = self.local_state()
        (local / "control.toml").write_text('[networking]\nnetwork_id = "custom"\n')
        before = {
            p: p.read_bytes()
            for p in (*local.iterdir(), *secrets.iterdir())
            if p.name != "control.toml"
        }
        for _ in range(2):
            result = self.run_script("dev-init")

            self.assertEqual(result.returncode, 0, result.stderr)

        config = tomllib.loads((local / "control.toml").read_text())

        self.assertEqual(
            config["redis"],
            {"url": "redis://redis:6379/0", "password_file": "/run/secrets/redis_password"},
        )
        self.assertEqual(config["networking"]["network_id"], "custom")

        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

        self.assertEqual((secrets / "redis_password").stat().st_mode & 0o777, 0o600)

    def test_init_tightens_existing_private_modes_without_rotation(self):
        local, secrets = self.local_state()
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        private = [
            local / "root-key.age",
            local / "root-passphrase",
            local / "relay-ca-key.pem",
            secrets / "relay_tls_key",
            secrets / "frontend_tls_key",
            secrets / "redis_password",
        ]
        before = {path: path.read_bytes() for path in private}
        for path in private:
            path.chmod(0o644)

        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        for path in private:
            self.assertEqual(path.read_bytes(), before[path])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)

    def test_atomic_write_unchanged_enforces_mode(self):
        path = self.root / "private"
        path.write_bytes(b"existing")
        path.chmod(0o644)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; from tooling import atomic_write; "
                "atomic_write(Path('private'), b'existing', 0o600)",
            ],
            cwd=self.root,
            env={**self.env, "PYTHONPATH": str(self.root / "scripts")},
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), b"existing")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_dev_static_config_is_trackable(self):
        import re

        shutil.copy(ROOT / ".gitignore", self.root / ".gitignore")
        subprocess.run(["/usr/bin/git", "init", "-q"], cwd=self.root, check=True)
        reference = re.search(
            r"TRAEFIK_CONFIG=([^\s]+)", (self.root / "scripts/dev.sh").read_text()
        )[1]
        relative = Path("deploy") / reference

        self.assertTrue((self.root / relative).is_file())

        result = subprocess.run(
            ["/usr/bin/git", "check-ignore", str(relative)],
            cwd=self.root,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1, "Fresh checkout omits ignored proxy config")

    def test_dev_init_preserves_existing_redis_configuration(self):
        local, _ = self.local_state()
        (local / "control.toml").write_text(
            '  [redis] # existing\nurl = "redis://custom:6379/1"\npassword_file = "/custom/password"\n'
        )
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            tomllib.loads((local / "control.toml").read_text())["redis"]["url"],
            "redis://custom:6379/1",
        )

    def test_dev_init_upgrades_legacy_relay_without_replacing_custom_values(self):
        local, _ = self.local_state()
        (local / "relay.toml").write_text(
            '[server]\nlisten_address = ":8081"\n[security]\nticket_key_file = "/run/secrets/relay_ticket_key"\n'
        )
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        config = tomllib.loads((local / "relay.toml").read_text())

        self.assertEqual(config["security"].get("tls_key_file"), "/run/secrets/relay_tls_key")
        self.assertEqual(config["server"].get("udp_port_max"), 51851)

    def test_dev_init_creates_relay_tls_once_without_replacing_trust(self):
        self.local_state()
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        secret_dir = self.root / "secrets"
        paths = [secret_dir / name for name in ("relay_tls_cert", "relay_tls_key", "relay_tls_ca")]
        for path in paths:
            self.assertTrue(path.is_file(), f"missing relay TLS file: {path.name}")

        self.assertEqual(paths[1].stat().st_mode & 0o777, 0o600)

        before = [path.read_bytes() for path in paths]
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([path.read_bytes() for path in paths], before)

    def test_dev_init_creates_verified_frontend_tls_without_rotating_ca(self):
        self.local_state()
        for _ in range(2):
            result = self.run_script("dev-init")

            self.assertEqual(result.returncode, 0, result.stderr)

            certificate = self.root / "secrets/frontend_tls_cert"

            self.assertTrue(certificate.is_file(), "frontend certificate missing")

            verification = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(self.root / "secrets/relay_tls_ca"),
                    str(certificate),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(verification.returncode, 0, verification.stderr)

            description = subprocess.check_output(
                ["openssl", "x509", "-in", str(certificate), "-noout", "-text"], text=True
            )

            self.assertIn("DNS:control.localhost", description)
            self.assertIn("DNS:relay.localhost", description)

            config = tomllib.loads((self.root / ".local/traefik/dynamic/routes.toml").read_text())
            transport = config["http"]["serversTransports"]["relay"]

            self.assertEqual(transport["serverName"], "relay")
            self.assertEqual(transport["rootCAs"], ["/run/secrets/relay_tls_ca"])
            self.assertNotIn("insecureSkipVerify", transport)
            self.assertEqual((self.root / "secrets/frontend_tls_key").stat().st_mode & 0o777, 0o600)

            if _ == 0:
                before = certificate.read_bytes()
            else:
                self.assertEqual(certificate.read_bytes(), before)

    def test_dev_init_refuses_to_replace_a_different_public_key(self):
        _, secrets = self.local_state()
        mounted_key = secrets / "root_public_key"
        mounted_key.write_text("previous-trust-anchor")
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(mounted_key.read_text(), "previous-trust-anchor")
        self.assertIn("root_public_key", result.stderr)

    def test_integration_local_starts_both_services_and_cleans_on_failure(self):
        self.cli(
            "docker",
            """
case "$1" in
  info) exit 0 ;;
  compose)
    printf '%s\\n' "$*" >> docker-calls
    case " $* " in
      *" up "*)
        test -s "$INTEGRATION_SECRETS_DIR/postgres_password" || exit 91
        test -s "$INTEGRATION_SECRETS_DIR/redis_password" || exit 92
        printf '%s' "$INTEGRATION_SECRETS_DIR" > secret-dir
        case " $* " in *" postgres redis "*) exit 19 ;; *) exit 93 ;; esac ;;
      *" down "*) exit 0 ;;
    esac ;;
esac
exit 94
""",
        )
        self.cli("go")
        result = self.run_script("integration-local")

        self.assertEqual(result.returncode, 19, result.stderr)

        calls = (self.root / "docker-calls").read_text().splitlines()

        self.assertEqual(len(calls), 2)
        self.assertIn("down --volumes --remove-orphans", calls[1])
        self.assertFalse(Path((self.root / "secret-dir").read_text()).exists())
        self.assertFalse((self.root / ".local").exists())

    def test_integration_local_rejects_bad_redis_port_before_initialization(self):
        self.cli("docker")
        self.env["INTEGRATION_REDIS_PORT"] = "80"
        result = self.run_script("integration-local")

        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((self.root / ".local").exists())

    def test_integration_local_encodes_credentials_and_passes_both_urls(self):
        sys.path.insert(0, str(self.root / "scripts"))

        try:
            from integration import test_urls

            urls = test_urls("+/secret=", "+/secret=", 55432, 56379)
        finally:
            sys.path.pop(0)

        self.assertIn("%2B%2Fsecret%3D", urls["TEST_DATABASE_URL"])
        self.assertIn("%2B%2Fsecret%3D", urls["TEST_REDIS_URL"])

        self.integration_events()
        self.cli("docker", 'printf "%s\\n" "$*" >> docker-calls\nexit 0\n')
        result = self.run_script("integration-local")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("down --volumes --remove-orphans", (self.root / "docker-calls").read_text())
        self.assertFalse((self.root / ".local").exists())

    def test_verify_rejects_formatting_changes_without_editing_sources(self):
        source = self.root / "unformatted.go"
        source.write_text("package sample\n")
        self.cli(
            "golangci-lint",
            "[ \"$1\" = fmt ] && [ \"$2\" = --diff ] || exit 88\nprintf '%s\\n' 'diff source.go'\nexit 1\n",
        )
        result = self.run_script("verify")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Run make fmt", result.stderr)
        self.assertIn("diff source.go", result.stdout)
        self.assertEqual(source.read_text(), "package sample\n")

    def test_format_check_preserves_formatter_failure_and_stops_other_tools(self):
        self.dependencies()
        self.cli("golangci-lint", "printf '%s\\n' 'formatter unavailable' >&2\nexit 7\n")
        self.cli("ruff", "touch later-format-tool\n")
        result = self.run_script("format-check")

        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("formatter unavailable", result.stderr)
        self.assertFalse((self.root / "later-format-tool").exists())

    def test_verify_runs_race_and_build_without_duplicate_architecture(self):
        self.cli("node")
        self.cli("make", "exit 0\n")
        self.cli("golangci-lint", "exit 0\n")
        self.cli("ruff", "exit 0\n")
        self.cli("npm", "exit 0\n")
        self.cli("djlint", "exit 0\n")
        self.cli("python3", "exit 0\n")
        self.cli("go", "printf '%s\\n' \"$*\" >> go-calls\n")
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (self.root / "go-calls").read_text().splitlines(),
            [
                "test -race ./cmd/... ./internal/... ./migrations/... -count=1 -timeout=90s",
                "build ./cmd/...",
            ],
        )

    def test_verify_portable_without_docker_ansible(self):
        self.cli("node")
        self.cli("make", 'printf "%s\\n" "$*" >> make-calls\n')
        for name in ("golangci-lint", "ruff", "npm", "djlint", "go", "python3"):
            self.cli(name)

        result = self.run_script("verify")

        self.assertEqual(result.returncode, 0, result.stderr)

        calls = (self.root / "make-calls").read_text()

        self.assertNotIn("compose-check", calls)
        self.assertNotIn("deploy-check", calls)

    def test_full_verify_runs_local_not_production_checks(self):
        self.env["FULL"] = "1"
        self.cli("make", 'printf "%s\\n" "$*" >> make-calls\n')
        self.cli("python3", 'printf "%s\\n" "$*" >> python-calls\n')
        for name in ("go", "node"):
            self.cli(name)
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "make-calls").read_text()
        self.assertIn("integration security", calls)
        self.assertIn("acceptance", calls)
        python = (self.root / "python-calls").read_text()
        self.assertIn("compose_check.py", python)
        self.assertNotIn("deploy_check.py", python)

    def test_full_verify_propagates_local_gate_failure(self):
        self.env["FULL"] = "1"
        self.cli("make", 'printf "%s\\n" "$*" >> make-calls\n')
        self.cli("python3", 'case "$*" in *compose_check.py*) exit 51 ;; esac\n')
        for name in ("go", "node"):
            self.cli(name)

        result = self.run_script("verify")

        self.assertEqual(result.returncode, 51)
        self.assertNotIn("acceptance", (self.root / "make-calls").read_text())

    def test_make_test_runs_browser_tests(self):
        self.cli("go")
        self.cli("python3")
        self.cli("node", 'printf "%s\\n" "$*" > node-calls\n')
        result = subprocess.run(
            ["/usr/bin/make", "-f", str(self.root / "Makefile"), "test"],
            cwd=self.bin,
            env=self.env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "node-calls").is_file(), "make test omitted browser tests")

    def test_inherited_python_does_not_escape_fixture(self):
        sentinel = self.root / "inherited-python"
        counter = self.root / "inherited-python-calls"
        sentinel.write_text('#!/bin/sh\nprintf x >> "$SENTINEL_FILE"\nexit 71\n')
        sentinel.chmod(0o755)
        # The child runs a real fixture test. Its fake tools must win over a
        # PYTHON value inherited from the developer's outer shell.
        returncode, output = self.run_nested_fixture_test(
            {"PYTHON": str(sentinel), "SENTINEL_FILE": str(counter)}
        )

        self.assertEqual(returncode, 0, output)
        self.assertFalse(counter.exists(), "fixture launched inherited PYTHON")

    def test_inherited_makeflags_does_not_escape_fixture(self):
        sentinel = self.root / "inherited-makeflags-python"
        counter = self.root / "inherited-makeflags-calls"
        sentinel.write_text('#!/bin/sh\nprintf x >> "$SENTINEL_FILE"\nexit 71\n')
        sentinel.chmod(0o755)
        returncode, output = self.run_nested_fixture_test(
            {"MAKEFLAGS": f"-- PYTHON={sentinel}", "SENTINEL_FILE": str(counter)}
        )

        self.assertEqual(returncode, 0, output)
        self.assertFalse(counter.exists(), "fixture launched inherited Make override")

    def run_nested_fixture_test(self, inherited):
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "unittest",
                "scripts.tests.test_tooling.ToolingTests.test_make_test_runs_browser_tests",
            ],
            cwd=ROOT,
            env={**os.environ, **inherited},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )

        try:
            try:
                stdout, stderr = process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self.fail("nested fixture test exceeded its 15-second bound")

            return process.returncode, stdout + stderr
        finally:
            # A recursive Make/Python descendant may outlive the direct child
            # and hold its pipes open. Own and terminate the entire group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

            process.communicate(timeout=5)

    def test_explicit_python_override_runs_once(self):
        sentinel = self.root / "explicit-python"
        counter = self.root / "explicit-python-calls"
        sentinel.write_text('#!/bin/sh\nprintf x >> "$SENTINEL_FILE"\nexit 0\n')
        sentinel.chmod(0o755)
        self.cli("go")
        self.cli("node")
        result = subprocess.run(
            ["/usr/bin/make", "-f", str(self.root / "Makefile"), f"PYTHON={sentinel}", "test"],
            cwd=self.bin,
            env={**self.env, "SENTINEL_FILE": str(counter)},
            capture_output=True,
            text=True,
            timeout=15,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(counter.read_text(), "x", "explicit override should run exactly once")

    def test_verify_uses_explicit_python_override_once(self):
        sentinel = self.root / "verify-python"
        counter = self.root / "verify-python-calls"
        sentinel.write_text('#!/bin/sh\nprintf x >> "$SENTINEL_FILE"\nexit 0\n')
        sentinel.chmod(0o755)
        for command in ("make", "python3", "node", "go"):
            self.cli(command)

        result = subprocess.run(
            ["/usr/bin/make", "-f", str(self.root / "Makefile"), f"PYTHON={sentinel}", "verify"],
            cwd=self.bin,
            env={**self.env, "SENTINEL_FILE": str(counter)},
            capture_output=True,
            text=True,
            timeout=15,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(counter.read_text(), "x", "verify ignored the explicit Python override")

    def test_dev_up_does_not_require_production_checks(self):
        self.cli("id", 'case "$1" in -u|-g) printf "501\\n" ;; esac\n')
        self.cli("docker")
        # Reject only the production checker; real dev command selects scope.
        self.cli(
            "python3",
            'case "$*" in --version) printf "Python 3.11.0\\n" ;; *compose_check.py*) exit 73 ;; esac\n',
        )
        result = self.run_script("dev", "up")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compose_check_is_read_only_and_rejects_public_redis(self):
        local, integration = self.local_compose_fixtures()
        local["services"]["redis"]["ports"] = [{"target": 6379, "published": "6379"}]
        self.serve_compose_fixtures(local, integration)
        result = self.run_script("compose-check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Redis", result.stderr)
        self.assertFalse((self.root / ".local").exists())
        self.assertFalse((self.root / "secrets").exists())

    def local_compose_fixtures(self):
        redis = {
            "secrets": [{"source": "redis_password"}],
            "command": [
                "cat /run/secrets/redis_password | sha256sum ; exec redis-server --aclfile /tmp/users.acl --maxmemory 128mb --maxmemory-policy noeviction"
            ],
            "mem_limit": "268435456",
            "healthcheck": {
                "test": [
                    "CMD-SHELL",
                    "REDISCLI_AUTH=$(cat /run/secrets/redis_password) redis-cli ping | grep -qx PONG",
                ]
            },
        }
        local = {
            "services": {
                "control": {
                    "secrets": [
                        {"source": name}
                        for name in (
                            "postgres_password",
                            "redis_password",
                            "session_signing_key",
                            "ceremony_encryption_key",
                            "relay_ticket_key",
                            "root_public_key",
                        )
                    ]
                },
                "migrate": {"secrets": [{"source": "postgres_password"}]},
                "db": {},
                "relay": {
                    "secrets": [
                        {"source": name}
                        for name in (
                            "relay_ticket_key",
                            "relay_tls_cert",
                            "relay_tls_key",
                            "relay_tls_ca",
                        )
                    ]
                },
                "redis": redis,
                "traefik": {
                    "cap_drop": ["ALL"],
                    "read_only": True,
                    "user": "65532:65532",
                    "secrets": [
                        {"source": name}
                        for name in ("relay_tls_ca", "frontend_tls_cert", "frontend_tls_key")
                    ],
                    "ports": [
                        {"host_ip": "127.0.0.1", "target": 8443, "published": "8443"},
                        {"host_ip": "127.0.0.1", "target": 8080, "published": "8088"},
                    ],
                },
            }
        }
        integration = {
            "services": {
                "redis": {
                    **redis,
                    "ports": [{"host_ip": "127.0.0.1", "target": 6379, "published": "56379"}],
                },
                "postgres": {
                    "ports": [{"host_ip": "127.0.0.1", "target": 5432, "published": "55432"}]
                },
            }
        }

        return local, integration

    def serve_compose_fixtures(self, local, integration):
        self.cli(
            "docker",
            'printf "%s\\n" "$*" >> docker-calls\n'
            + "case \"$*\" in *compose.integration.yaml*) printf '%s\\n' '"
            + json.dumps(integration)
            + "' ;; *) printf '%s\\n' '"
            + json.dumps(local)
            + "' ;; esac\n",
        )

    def test_single_local_stack_preserves_security_contract(self):
        local, integration = self.local_compose_fixtures()
        self.serve_compose_fixtures(local, integration)
        result = self.run_script("compose-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / ".local").exists())
        calls = (self.root / "docker-calls").read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertFalse(any("compose.local.yaml" in call for call in calls))

    def test_local_validation_rejects_unsafe_proxy(self):
        for fault in ("socket", "public", "capability", "tls"):
            with self.subTest(fault=fault):
                local, integration = self.local_compose_fixtures()
                proxy = local["services"]["traefik"]
                if fault == "socket":
                    proxy["volumes"] = [{"source": "/var/run/docker.sock"}]
                elif fault == "public":
                    proxy["ports"][0]["host_ip"] = "0.0.0.0"
                elif fault == "capability":
                    local["services"]["relay"]["cap_add"] = ["NET_ADMIN"]
                else:
                    routes = self.root / "deploy/traefik/routes.toml"
                    routes.write_text(
                        '[http.serversTransports.relay]\nserverName="relay"\n'
                        'rootCAs=["/run/secrets/relay_tls_ca"]\ninsecureSkipVerify=true\n'
                    )

                self.serve_compose_fixtures(local, integration)
                result = self.run_script("compose-check")

                self.assertNotEqual(result.returncode, 0, fault + " was accepted")

                expected = {
                    "socket": "socket",
                    "public": "loopback",
                    "capability": "capabilities",
                    "tls": "TLS",
                }

                self.assertIn(expected[fault], result.stderr)

    def test_local_relay_cannot_receive_identity_secrets(self):
        local, integration = self.local_compose_fixtures()
        local["services"]["relay"]["secrets"].append({"source": "ceremony_encryption_key"})
        self.serve_compose_fixtures(local, integration)
        result = self.run_script("compose-check")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay", result.stderr)

    def test_init_rejects_bad_port_without_writing_state(self):
        self.env["DEV_HTTPS_PORT"] = "80"
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / ".local").exists())
        self.assertFalse((self.root / "secrets").exists())

    def test_init_updates_managed_https_port_without_rotating_certificates(self):
        local, secrets = self.local_state()
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        before = (secrets / "frontend_tls_cert").read_bytes()
        self.env["DEV_HTTPS_PORT"] = "9443"
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)

        control = tomllib.loads((local / "control.toml").read_text())

        self.assertEqual(control["server"]["public_url"], "https://control.localhost:9443")
        self.assertEqual((secrets / "frontend_tls_cert").read_bytes(), before)

    def test_init_preserves_indented_toml_sections_and_comments(self):
        local, _ = self.local_state()
        (local / "relay.toml").write_text('  [server] # custom\nlisten_address = ":8081"\n')
        result = self.run_script("dev-init")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("# custom", (local / "relay.toml").read_text())
        self.assertEqual(
            tomllib.loads((local / "relay.toml").read_text())["server"]["udp_port_max"], 51851
        )

    def test_init_failed_certificate_generation_publishes_no_tls(self):
        self.local_state()
        self.cli("openssl", "exit 23\n")
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "secrets/relay_tls_ca").exists())
        self.assertFalse((self.root / ".local/relay-ca-key.pem").exists())

    def test_vm_up_honors_instance_and_other_cwd(self):
        self.env["LIMA_INSTANCE"] = "custom-vm"
        self.cli("limactl", 'printf "%s\\n" "$*" >> "' + str(self.root / "lima-calls") + '"\n')
        result = subprocess.run(
            ["sh", str(self.root / "scripts/vm-up.sh")],
            cwd=self.bin,
            env=self.env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--name custom-vm", (self.root / "lima-calls").read_text())

    def test_vm_up_rejects_existing_home_mount(self):
        self.env["LIMA_INSTANCE"] = "custom-vm"
        config = json.dumps({"config": {"mounts": [{"location": "~", "writable": True}]}})
        self.cli(
            "limactl",
            f"case \"$*\" in *--json*) printf '%s\\n' '{config}' ;; "
            '*--format*) printf "custom-vm\\n" ;; *) exit 99 ;; esac\n',
        )
        result = self.run_script("vm-up")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsafe VM mounts", result.stderr)

    def test_init_rejects_incomplete_tls_without_replacing_private_key(self):
        _, secrets = self.local_state()
        key = secrets / "relay_tls_key"
        key.write_text("existing-private-material")
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", result.stderr.lower())
        self.assertEqual(key.read_text(), "existing-private-material")
        self.assertFalse((secrets / "relay_tls_ca").exists())

    def test_init_root_generation_failure_publishes_no_state(self):
        self.cli("go", "printf '%s\\n' \"$@\" > go-args\nexit 23\n")
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "secrets").exists())
        self.assertFalse((self.root / ".local").exists())

        arguments = (self.root / "go-args").read_text().splitlines()

        self.assertIn("--key", arguments)
        self.assertIn("--passphrase-file", arguments)

    def test_init_works_from_another_directory(self):
        self.local_state()
        result = subprocess.run(
            [sys.executable, str(self.root / "scripts/dev_init.py")],
            cwd=self.bin,
            env=self.env,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / ".local/control.toml").is_file())
        self.assertFalse((self.bin / ".local").exists())

    def test_integration_signal_cleans_disposable_project(self):
        self.cli("go")
        self.cli(
            "docker",
            'case " $* " in\n  *" up "*) printf \'%s\' "$INTEGRATION_SECRETS_DIR" > secret-dir; exec sleep 30 ;;\n  *" down "*) printf \'%s\' "$*" > cleanup-call ;;\nesac\nexit 0\n',
        )
        process = subprocess.Popen(
            [sys.executable, str(self.root / "scripts/integration.py")],
            cwd=self.bin,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        marker = self.root / "secret-dir"
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)

        self.assertTrue(marker.exists(), "integration services never started")

        process.send_signal(signal.SIGTERM)
        output, error = process.communicate(timeout=10)

        self.assertEqual(process.returncode, 143, output + error)
        self.assertIn("down --volumes --remove-orphans", (self.root / "cleanup-call").read_text())
        self.assertFalse(Path(marker.read_text()).exists())

    def test_integration_isolated_ignores_external_urls_and_serializes_packages(self):
        self.integration_events()
        current = (self.bin / "go").read_text()
        guard = '[ "$TEST_DATABASE_URL" != "postgres://test" ] || exit 91\ncase " $* " in *" -p=1 "*) ;; *) exit 92 ;; esac\n'
        (self.bin / "go").write_text(current.replace("#!/bin/sh\n", "#!/bin/sh\n" + guard))
        self.cli("docker")
        result = self.run_script("integration-local")

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ci_calls_only_existing_make_targets(self):
        import re

        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        targets = re.findall(r"\bmake ([a-z-]+)", workflow)

        self.assertTrue({"verify", "security", "integration", "acceptance"} <= set(targets))
        self.assertNotIn("ci", targets)

        for target in targets:
            result = subprocess.run(
                ["make", "-n", "-f", str(self.root / "Makefile"), target],
                cwd=self.bin,
                env=self.env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_integration_cleanup_failure_preserves_go_exit_code(self):
        self.cli("go", "exit 17\n")
        self.cli(
            "docker",
            'case " $* " in *" up "*) printf "%s" "$INTEGRATION_SECRETS_DIR" > secret-dir ;; *" down "*) exit 19 ;; esac\n',
        )
        result = self.run_script("integration-local")

        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("cleanup failed", result.stderr)
        self.assertFalse(Path((self.root / "secret-dir").read_text()).exists())

    def test_full_verify_stops_on_first_gate_failure(self):
        self.cli(
            "make",
            'printf "%s\\n" "$*" >> "' + str(self.root / "make-calls") + '"\nexit 17\n',
        )
        result = subprocess.run(
            [
                "/usr/bin/make",
                "-f",
                str(self.root / "Makefile"),
                "verify",
                "FULL=1",
                "MAKE=" + str(self.bin / "make"),
            ],
            cwd=self.bin,
            env=self.env,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)

        calls = (self.root / "make-calls").read_text().splitlines()

        self.assertEqual(len(calls), 1)
        self.assertIn("lint", calls[0])

    def test_e2e_doctor_linux_requires_native_tools_not_lima(self):
        self.dependencies()
        self.cli("uname", "printf Linux\n")
        self.cli("id", "printf 1000\n")
        for name in ("ip", "nft", "wg", "systemctl", "resolvectl"):
            self.cli(name)

        result = self.run_script("doctor", "e2e")

        self.assertNotEqual(result.returncode, 0)

        for name in ("ip", "nft", "wg", "systemctl", "resolvectl"):
            self.assertIn(name + ":", result.stdout)

        self.assertIn("requires root", result.stderr)
        self.assertNotIn("limactl", result.stderr)


if __name__ == "__main__":
    unittest.main()
