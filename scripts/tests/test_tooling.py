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
        self.temp = tempfile.TemporaryDirectory(prefix="go-tunnels-tooling-")
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
            "deploy-check": "deploy_check",
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

    def integration_events(self, *, skip=False, missing_redis=False, missing_sessions=False):
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
        for module in ("audit", "identity", "invites", "policy", "routes", "services", "snapshots"):
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
                "Package": "example/internal/app/control/storage",
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

    def test_dev_init_adds_redis_and_preserves_keys_on_repeat(self):
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
            "[ \"$1\" = fmt ] && [ \"$2\" = --diff ] || exit 88\nprintf '%s\\n' 'diff source.go'\n",
        )
        result = self.run_script("verify")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Run make fmt", result.stderr)
        self.assertEqual(source.read_text(), "package sample\n")

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

    def test_full_verify_runs_required_gates(self):
        self.env["FULL"] = "1"
        self.cli("make", 'printf "%s\\n" "$*" >> make-calls\n')
        self.cli("python3", 'printf "%s\\n" "$*" >> python-calls\n')
        for name in ("go", "node", "ansible-lint"):
            self.cli(name)
        result = self.run_script("verify")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.root / "make-calls").read_text()
        self.assertIn("integration security", calls)
        self.assertIn("acceptance", calls)
        python = (self.root / "python-calls").read_text()
        self.assertIn("compose_check.py", python)
        self.assertIn("deploy_check.py", python)

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
        services = {
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
            "redis": {
                "secrets": [{"source": "redis_password"}],
                "ports": [{"target": 6379, "published": "6379"}],
            },
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
        production = {
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
                "redis": redis,
                "traefik": {
                    "cap_drop": ["ALL"],
                    "read_only": True,
                    "user": "65532:65532",
                    "secrets": [{"source": "relay_tls_ca"}],
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
        local = json.loads(json.dumps(production))
        local["services"]["relay"] = {}
        local["services"]["traefik"]["secrets"] += [
            {"source": "frontend_tls_cert"},
            {"source": "frontend_tls_key"},
        ]
        self.cli(
            "docker",
            "case \"$*\" in *compose.local.yaml*) printf '%s\\n' '"
            + json.dumps(local)
            + "' ;; *compose.integration.yaml*) printf '%s\\n' '"
            + json.dumps(integration)
            + "' ;; *) printf '%s\\n' '"
            + json.dumps(production)
            + "' ;; esac\n",
        )
        result = self.run_script("compose-check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / ".local").exists())

        # A socket grants host-level authority even if it is mounted read-only.
        production["services"]["traefik"]["volumes"] = [
            {"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}
        ]
        local = json.loads(json.dumps(production))
        local["services"]["relay"] = {}
        local["services"]["traefik"]["secrets"] += [
            {"source": "frontend_tls_cert"},
            {"source": "frontend_tls_key"},
        ]
        self.cli(
            "docker",
            "case \"$*\" in *compose.local.yaml*) printf '%s\\n' '"
            + json.dumps(local)
            + "' ;; *compose.integration.yaml*) printf '%s\\n' '"
            + json.dumps(integration)
            + "' ;; *) printf '%s\\n' '"
            + json.dumps(production)
            + "' ;; esac\n",
        )
        result = self.run_script("compose-check")
        self.assertNotEqual(result.returncode, 0, "proxy Docker socket was accepted")
        self.assertIn("socket", result.stderr)

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
        self.cli("go", "exit 23\n")
        result = self.run_script("dev-init")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "secrets").exists())
        self.assertFalse((self.root / ".local").exists())

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

    def test_deploy_does_not_retain_legacy_migration_framework(self):
        import yaml

        play = yaml.safe_load((ROOT / "deploy/ansible/site.yml").read_text())[0]
        commands = [handler["ansible.builtin.command"] for handler in play["handlers"]]
        rollout = next(
            command for command in commands if "cmd" in command and " up " in command["cmd"]
        )
        config = rollout["cmd"].split("-f ", 1)[1].split()[0]
        project_dir = str(Path(config).parent)
        self.assertEqual(project_dir, "deploy")
        self.assertFalse(any("legacy_services" in str(command) for command in commands))
        self.assertFalse(any("docker', 'stop" in str(command) for command in commands))

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
