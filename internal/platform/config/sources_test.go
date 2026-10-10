package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func validControlFile(extra string) string {
	return `[server]
listen_address = ":8080"
public_url = "https://control.example"
[database]
url = "postgres://user@db/home"
[auth]
rp_id = "control.example"
rp_origin = "https://control.example"
session_signing_key = "01234567890123456789012345678901"
ceremony_encryption_key = "abcdefghijklmnopqrstuvwxyzABCDEF"
session_ttl = "12h"
ceremony_ttl = "5m"
[relay]
public_url = "wss://relay.example/relay/udp"
ticket_key = "01234567890123456789012345678901"
[security]
root_public_key_file = "root.pub"
` + extra
}

func TestControlRejectsOldRelayEndpointAtStartup(t *testing.T) {
	canonical := validControlFile("")

	if _, err := LoadControl(Sources{File: writeConfig(t, canonical), Env: noEnv}); err != nil {
		t.Fatalf("canonical relay endpoint rejected: %v", err)
	}

	old := strings.Replace(canonical, "/relay/udp\"", "/relay/udp/v2\"", 1)

	if _, err := LoadControl(Sources{File: writeConfig(t, old), Env: noEnv}); err == nil {
		t.Fatal("old relay endpoint accepted at startup")
	}
}

func TestRemovedRelaySettingsAreRejected(t *testing.T) {
	for _, setting := range []string{"udp_address", "stun_server"} {
		t.Run("node "+setting, func(t *testing.T) {
			path := writeConfig(t, "[relay]\n"+setting+" = 'obsolete'\n")

			if _, err := LoadClient(Sources{File: path, Env: noEnv}); err == nil {
				t.Fatal("obsolete node relay setting accepted")
			}
		})
	}

	t.Run("control public UDP", func(t *testing.T) {
		body := strings.Replace(
			validControlFile(""),
			"[relay]\n",
			"[relay]\npublic_udp_address = 'relay.example:51820'\n",
			1,
		)

		path := writeConfig(t, body)

		if _, err := LoadControl(Sources{File: path, Env: noEnv}); err == nil {
			t.Fatal("obsolete control public UDP setting accepted")
		}
	})
}

func TestControlSelectedInlineSecretDoesNotOpenLowerFile(t *testing.T) {
	path := writeConfig(
		t,
		validControlFile("\n[redis]\npassword_file = '/definitely/missing/redis-secret'\n"),
	)
	t.Setenv("HOMEHARBOR_REDIS_PASSWORD", "chosen-secret")

	cfg, err := LoadControl(Sources{File: path})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Redis.Password != "chosen-secret" {
		t.Fatalf("selected Redis password was ignored")
	}
}

func TestPresentEmptyEnvironmentSecretDoesNotFallBackToFile(t *testing.T) {
	path := writeConfig(t, strings.Replace(validControlFile(""),
		`session_signing_key = "01234567890123456789012345678901"`,
		`session_signing_key_file = "/definitely/missing/signing-key"`, 1))

	_, err := LoadControl(Sources{File: path, Env: func(key string) (string, bool) {
		if key == "HOMEHARBOR_AUTH_SESSION_SIGNING_KEY" {
			return "", true
		}

		return "", false
	}})

	if err == nil || strings.Contains(err.Error(), "file unavailable") {
		t.Fatalf("empty selected secret should fail semantic validation: %v", err)
	}
}

func TestControlRejectsUnknownTOMLKey(t *testing.T) {
	path := writeConfig(t, validControlFile("\n[observability]\nunknwon = 'oops'\n"))

	if _, err := LoadControl(
		Sources{File: path},
	); err == nil ||
		!strings.Contains(err.Error(), "observability.unknwon") {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestMissingConfigFileReportsReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.toml")

	if _, err := LoadControl(Sources{File: path, Env: noEnv}); err == nil ||
		!strings.Contains(err.Error(), "read config file") {
		t.Fatalf("missing file error = %v", err)
	}
}

func TestDatabaseOnlyRejectsUnknownElsewhereWithoutOpeningSecrets(t *testing.T) {
	path := writeConfig(
		t,
		validControlFile("\n[redis]\npassword_file = '/definitely/missing/redis-secret'\n"),
	)

	if _, err := LoadDatabase(Sources{File: path}); err != nil {
		t.Fatalf("valid full schema with unrelated missing secret: %v", err)
	}

	path = writeConfig(t, validControlFile("\n[redis]\nunknwon = 'oops'\n"))

	if _, err := LoadDatabase(
		Sources{File: path},
	); err == nil ||
		!strings.Contains(err.Error(), "redis.unknwon") {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestSourcesPreserveExplicitFalseZeroAndEmpty(t *testing.T) {
	path := writeConfig(
		t,
		"[node]\nrefresh = true\nname = 'from-file'\n[wireguard]\nlisten_port = 51820\n",
	)

	cfg, err := LoadClient(Sources{
		File: path,
		Env: func(key string) (string, bool) {
			if key == "HOMEHARBOR_NODE_NAME" {
				return "", true
			}

			return "", false
		},
		Flags: map[string]string{"node.refresh": "false", "wireguard.listen_port": "0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Identity.Refresh || cfg.Identity.Name != "" || cfg.WireGuard.ListenPort != 0 {
		t.Fatalf("explicit overrides were lost: refresh=%v name=%q port=%d",
			cfg.Identity.Refresh, cfg.Identity.Name, cfg.WireGuard.ListenPort)
	}
}

func TestSourcesChooseOnlyFinalSecret(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "chosen")

	if err := os.WriteFile(secretPath, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	path := writeConfig(
		t,
		"[database]\nurl = 'postgres://user@db/home'\npassword_file = '/definitely/missing/lower'\n",
	)
	for _, tc := range []struct {
		name  string
		flags map[string]string
		want  string
	}{
		{"higher inline", map[string]string{"database.password": "from-flag"}, "from-flag"},
		{"higher file", map[string]string{"database.password_file": secretPath}, "from-file"},
		{"explicit empty", map[string]string{"database.password": ""}, ""},
		{"empty file clears lower source", map[string]string{"database.password_file": ""}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadDatabase(Sources{File: path, Env: noEnv, Flags: tc.flags})
			if err != nil {
				t.Fatal(err)
			}

			if cfg.Password != tc.want {
				t.Fatal("wrong final password")
			}
		})
	}

	inlinePath := writeConfig(
		t,
		"[database]\nurl = 'postgres://user@db/home'\npassword = 'lower-inline'\n",
	)

	cfg, err := LoadDatabase(Sources{File: inlinePath, Env: noEnv, Flags: map[string]string{
		"database.password_file": secretPath,
	}})

	if err != nil || cfg.Password != "from-file" {
		t.Fatalf("higher file failed to override lower inline: %v", err)
	}
}

func TestOptionalNodeSecretFileCanBeExplicitlyCleared(t *testing.T) {
	path := writeConfig(t, "[node]\nenrollment_token_file = '/definitely/missing/token'\n")

	cfg, err := LoadClient(Sources{File: path, Env: noEnv, Flags: map[string]string{
		"node.enrollment_token_file": "",
	}})

	if err != nil || cfg.Identity.Token != "" {
		t.Fatalf("cleared token file: token=%q error=%v", cfg.Identity.Token, err)
	}
}

func TestSourcesRejectSameSourceSecretConflict(t *testing.T) {
	path := writeConfig(
		t,
		"[database]\nurl = 'postgres://user@db/home'\npassword = 'inline'\npassword_file = 'missing'\n",
	)

	if _, err := LoadDatabase(
		Sources{File: path, Env: noEnv},
	); err == nil ||
		!strings.Contains(err.Error(), "conflict") {
		t.Fatalf("same-file secret conflict = %v", err)
	}

	path = writeConfig(t, "[database]\nurl = 'postgres://user@db/home'\n")

	if _, err := LoadDatabase(Sources{File: path, Env: noEnv, Flags: map[string]string{
		"database.password": "sensitive-flag-value", "database.password_file": "missing",
	}}); err == nil || strings.Contains(err.Error(), "sensitive-flag-value") {
		t.Fatalf("same-flags conflict or leaked value: %v", err)
	}
}

func TestSourcesValidateFinalURLAndRuntime(t *testing.T) {
	path := writeConfig(t, "[database]\nurl = 'postgres://user@db/home'\n")

	if _, err := LoadDatabase(Sources{File: path, Env: noEnv, Flags: map[string]string{
		"database.url": "not-a-url-with-secret-sentinel",
	}}); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("invalid URL error or leaked value: %v", err)
	}

	nodePath := writeConfig(t, "[runtime]\noperation_timeout = '45s'\n")

	if _, err := LoadClient(Sources{File: nodePath, Env: noEnv, Flags: map[string]string{
		"runtime.operation_timeout": "0s",
	}}); err == nil {
		t.Fatal("zero runtime timeout accepted")
	}

	controlPath := writeConfig(t, validControlFile(""))
	for _, ttl := range []map[string]string{
		{"auth.session_ttl": "not-a-duration"},
		{"relay.ticket_ttl": ""},
	} {
		if _, err := LoadControl(Sources{File: controlPath, Env: noEnv, Flags: ttl}); err == nil {
			t.Fatalf("invalid final TTL accepted: %v", ttl)
		}
	}
}

func TestMalformedSecretConfigErrorDoesNotEchoValue(t *testing.T) {
	path := writeConfig(t, "[database]\npassword = 'secret-sentinel-without-close\n")

	_, err := LoadDatabase(Sources{File: path, Env: noEnv})

	if err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatalf("decode error leaked secret source line: %v", err)
	}
}

func noEnv(string) (string, bool) { return "", false }
