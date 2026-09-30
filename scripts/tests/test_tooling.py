"""Run real entrypoints in disposable repositories; fake only external CLIs."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ToolingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="go-tunnels-tooling-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "scripts", self.root / "scripts")
        shutil.copytree(ROOT / "config", self.root / "config")
        shutil.copytree(ROOT / "deploy", self.root / "deploy")
        shutil.copy(ROOT / "Makefile", self.root / "Makefile")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {**os.environ, "PATH": f"{self.bin}:/usr/bin:/bin"}
        for key in ("TEST_DATABASE_URL", "TEST_REDIS_URL", "INTEGRATION_POSTGRES_PORT", "INTEGRATION_REDIS_PORT"):
            self.env.pop(key, None)

    def cli(self, name, body="exit 0\n"):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)

    def run_script(self, name, *args):
        return subprocess.run(["/bin/sh", f"scripts/{name}.sh", *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True)

    def dependencies(self):
        for name in ("go", "git", "golangci-lint", "python3"):
            self.cli(name)

    def integration_events(self, *, skip=False, missing_redis=False, missing_sessions=False):
        events = [
            {"Action": "pass", "Package": "example/internal/control/devices/storage", "Test": "TestPostgresEnrollment"},
            {"Action": "pass", "Package": "example/migrations", "Test": "TestConcurrentUpSerializesWithAdvisoryLock"},
        ]
        for module in ("audit", "identity", "invites", "policy", "routes", "services", "snapshots"):
            events.append({"Action": "pass", "Package": f"example/internal/control/{module}/storage", "Test": "TestPostgresContract"})
        events.append({"Action": "pass", "Package": "example/internal/app/control/storage", "Test": "TestPostgresActivation"})
        if not missing_redis:
            events.append({"Action": "skip" if skip else "pass", "Package": "example/internal/platform/redissecurity", "Test": "TestRedisChallenge"})
        if not missing_sessions:
            events.append({"Action": "pass", "Package": "example/internal/control/identity/redis", "Test": "TestRedisSessionSharedTTLAndRevoke"})
        self.cli("go", "[ \"$1\" = test ] || exit 99\n[ \"$2\" = -json ] || exit 98\n" +
                 "printf '%s\\n' '" + "\n".join(json.dumps(e) for e in events) + "'\n")
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

    def test_ios_doctor_does_not_require_go(self):
        self.cli("xcodebuild")
        result = self.run_script("doctor", "ios")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_e2e_doctor_requires_linux_vm_tools(self):
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
        for name, length in (("postgres_password", 44), ("redis_password", 44), ("relay_ticket_key", 44), ("session_signing_key", 64), ("ceremony_encryption_key", 32)):
            (secrets / name).write_text("A" * length)
        return local, secrets

    def test_dev_init_adds_redis_and_preserves_keys_on_repeat(self):
        local, secrets = self.local_state()
        (local / "control.toml").write_text('[networking]\nnetwork_id = "custom"\n')
        before = {p: p.read_bytes() for p in (*local.iterdir(), *secrets.iterdir()) if p.name != "control.toml"}
        for _ in range(2):
            result = self.run_script("dev-init")
            self.assertEqual(result.returncode, 0, result.stderr)
        config = tomllib.loads((local / "control.toml").read_text())
        self.assertEqual(config["redis"], {"url": "redis://redis:6379/0", "password_file": "/run/secrets/redis_password"})
        self.assertEqual(config["networking"]["network_id"], "custom")
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertEqual((secrets / "redis_password").stat().st_mode & 0o777, 0o600)

    def test_dev_init_preserves_existing_redis_configuration(self):
        local, _ = self.local_state()
        (local / "control.toml").write_text('  [redis] # existing\nurl = "redis://custom:6379/1"\npassword_file = "/custom/password"\n')
        result = self.run_script("dev-init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(tomllib.loads((local / "control.toml").read_text())["redis"]["url"], "redis://custom:6379/1")

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

    def test_dev_init_refuses_to_replace_a_different_public_key(self):
        _, secrets = self.local_state()
        mounted_key = secrets / "root_public_key"
        mounted_key.write_text("previous-trust-anchor")
        result = self.run_script("dev-init")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(mounted_key.read_text(), "previous-trust-anchor")
        self.assertIn("root_public_key", result.stderr)

    def test_integration_local_starts_both_services_and_cleans_on_failure(self):
        self.cli("docker", '''
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
''')
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
        self.integration_events()
        self.cli("openssl", "printf '%s' '+/secret='\n")
        self.cli("docker", 'printf "%s\\n" "$*" >> docker-calls\nexit 0\n')
        current = (self.bin / "go").read_text()
        guard = '''[ "$TEST_DATABASE_URL" = 'postgres://go_tunnels:%2B%2Fsecret%3D@127.0.0.1:55432/go_tunnels?sslmode=disable' ] || exit 90
[ "$TEST_REDIS_URL" = 'redis://:%2B%2Fsecret%3D@127.0.0.1:56379/0' ] || exit 91
'''
        (self.bin / "go").write_text(current.replace("#!/bin/sh\n", "#!/bin/sh\n" + guard))
        result = self.run_script("integration-local")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("down --volumes --remove-orphans", (self.root / "docker-calls").read_text())
        self.assertFalse((self.root / ".local").exists())

    def test_fmt_check_reports_changes_without_editing_sources(self):
        source = self.root / "unformatted.go"
        source.write_text("package sample\n")
        self.cli("golangci-lint", "[ \"$1\" = fmt ] && [ \"$2\" = --diff ] || exit 88\nprintf '%s\\n' 'diff source.go'\n")
        result = subprocess.run(["make", "fmt-check"], cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Run make fmt", result.stderr)
        self.assertEqual(source.read_text(), "package sample\n")

    def test_verify_runs_unit_vet_build_and_architecture(self):
        self.cli("make", "exit 0\n")
        self.cli("go", "printf '%s\\n' \"$*\" >> go-calls\n")
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "go-calls").read_text().splitlines(),
                         ["test ./...", "vet ./...", "build ./cmd/...", "test ./internal/architecture -count=1"])

    def test_compose_check_is_read_only_and_rejects_public_redis(self):
        services = {
            "control": {"secrets": [{"source": name} for name in ("postgres_password", "redis_password", "session_signing_key", "ceremony_encryption_key", "relay_ticket_key", "root_public_key")]},
            "migrate": {"secrets": [{"source": "postgres_password"}]},
            "redis": {"secrets": [{"source": "redis_password"}], "ports": [{"target": 6379, "published": "6379"}]},
            "caddy": {"cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"]},
        }
        self.cli("docker", "printf '%s\\n' '" + json.dumps({"services": services}) + "'\n")
        result = self.run_script("compose-check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Redis", result.stderr)
        self.assertFalse((self.root / ".local").exists())
        self.assertFalse((self.root / "secrets").exists())

    def test_compose_check_accepts_numeric_string_memory_limit(self):
        redis = {
            "secrets": [{"source": "redis_password"}],
            "command": ["cat /run/secrets/redis_password | sha256sum ; exec redis-server --aclfile /tmp/users.acl --maxmemory 128mb --maxmemory-policy noeviction"],
            "mem_limit": "268435456",
            "healthcheck": {"test": ["CMD-SHELL", "REDISCLI_AUTH=$(cat /run/secrets/redis_password) redis-cli ping | grep -qx PONG"]},
        }
        production = {"services": {
            "control": {"secrets": [{"source": name} for name in ("postgres_password", "redis_password", "session_signing_key", "ceremony_encryption_key", "relay_ticket_key", "root_public_key")]},
            "migrate": {"secrets": [{"source": "postgres_password"}]},
            "redis": redis,
            "caddy": {"cap_drop": ["ALL"], "cap_add": ["NET_BIND_SERVICE"]},
        }}
        integration = {"services": {
            "redis": {**redis, "ports": [{"host_ip": "127.0.0.1", "target": 6379, "published": "56379"}]},
            "postgres": {"ports": [{"host_ip": "127.0.0.1", "target": 5432, "published": "55432"}]},
        }}
        self.cli("docker", "case \"$*\" in *compose.integration.yaml*) printf '%s\\n' '" + json.dumps(integration) + "' ;; *) printf '%s\\n' '" + json.dumps(production) + "' ;; esac\n")
        result = self.run_script("compose-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / ".local").exists())


if __name__ == "__main__":
    unittest.main()
