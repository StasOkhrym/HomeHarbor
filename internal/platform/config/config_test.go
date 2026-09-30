package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadControlResolvesFileSecretAndEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "database-password")
	signingKeyPath := filepath.Join(dir, "session-key")
	ceremonyKeyPath := filepath.Join(dir, "ceremony-key")
	relayKeyPath := filepath.Join(dir, "relay-key")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signingKeyPath, []byte("01234567890123456789012345678901\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ceremonyKeyPath, []byte("abcdefghijklmnopqrstuvwxyzABCDEF\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayKeyPath, []byte("01234567890123456789012345678901\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "control.toml")
	content := `[server]
listen_address = ":8080"
public_url = "https://tunnel.example.com"
[database]
url = "postgres://tunnel@db/tunnel"
password_file = "` + secretPath + `"
[auth]
rp_id = "tunnel.example.com"
rp_origin = "https://tunnel.example.com"
session_signing_key_file = "` + signingKeyPath + `"
ceremony_encryption_key_file = "` + ceremonyKeyPath + `"
session_ttl = "12h"
ceremony_ttl = "5m"
[relay]
public_url = "https://relay.example.com"
ticket_key_file = "` + relayKeyPath + `"
ticket_ttl = "5m"
[observability]
metrics_address = ":9090"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_TUNNELS_SERVER_LISTEN_ADDRESS", ":8181")

	cfg, err := LoadControl(configPath)
	if err != nil {
		t.Fatalf("LoadControl() error = %v", err)
	}
	if cfg.Server.ListenAddress != ":8181" {
		t.Fatalf("listen address = %q", cfg.Server.ListenAddress)
	}
	if cfg.Database.Password != "secret" {
		t.Fatalf("database password = %q", cfg.Database.Password)
	}
}

func TestControlValidationRejectsUnsafeAuthenticationSettings(t *testing.T) {
	valid := Control{Server: Server{ListenAddress: ":8080", PublicURL: "https://tunnel.example.com"}, Database: Database{URL: "postgres://db/tunnel"}, Auth: Auth{RPID: "tunnel.example.com", RPOrigin: "https://tunnel.example.com", SessionSigningKey: "01234567890123456789012345678901", CeremonyEncryptionKey: "abcdefghijklmnopqrstuvwxyzABCDEF", SessionTTL: "12h", CeremonyTTL: "5m"}, Relay: Relay{PublicURL: "wss://relay.example.com", TicketKey: "01234567890123456789012345678901", TicketTTL: "5m"}}
	tests := []struct {
		name   string
		mutate func(*Control)
	}{
		{"insecure origin", func(c *Control) { c.Auth.RPOrigin = "http://tunnel.example.com" }},
		{"RP mismatch", func(c *Control) { c.Auth.RPID = "other.example.com" }},
		{"short signing key", func(c *Control) { c.Auth.SessionSigningKey = "short" }},
		{"wrong ceremony key size", func(c *Control) { c.Auth.CeremonyEncryptionKey = "short" }},
		{"invalid session TTL", func(c *Control) { c.Auth.SessionTTL = "0s" }},
		{"invalid ceremony TTL", func(c *Control) { c.Auth.CeremonyTTL = "not-a-duration" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := valid
			test.mutate(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatal("validate() error = nil")
			}
		})
	}
}

func TestLoadControlRejectsMissingRequiredValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.toml")
	if err := os.WriteFile(path, []byte("[server]\nlisten_address = \":8080\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadControl(path); err == nil {
		t.Fatal("LoadControl() error = nil, want validation error")
	}
}
