package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeRejectsExplicitInvalid(t *testing.T) {
	for _, input := range []string{
		"auth_per_minute = 0", "auth_per_minute = 31",
		"onboarding_per_minute = 61", "redis_timeout = '0s'",
		"claim_ttl = '3m'", "credential_ttl = '16m'",
		"relay_max_peers = -1", "http_read_timeout = '6m'",
	} {
		t.Run(input, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "node.toml")

			if err := os.WriteFile(path, []byte("[runtime]\n"+input+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := LoadClient(Sources{File: path}); err == nil {
				t.Fatal("explicit invalid runtime setting was accepted")
			}
		})
	}
}

func TestRuntimeDefaultsAndOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.toml")

	if err := os.WriteFile(
		path,
		[]byte("[runtime]\noperation_timeout = '45s'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClient(Sources{File: path})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Runtime.OperationTimeout != 45*time.Second ||
		cfg.Runtime.CleanupTimeout != 5*time.Second {
		t.Fatalf(
			"operation/cleanup = %v/%v",
			cfg.Runtime.OperationTimeout,
			cfg.Runtime.CleanupTimeout,
		)
	}
	if cfg.Runtime.AuthPerMinute != 5 || cfg.Runtime.OnboardingPerMinute != 10 {
		t.Fatal("safe quota defaults changed")
	}
}
