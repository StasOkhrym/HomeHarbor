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
[security]
root_public_key_file = "/run/secrets/root_public_key"
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

func TestLoadDatabaseRequiresOnlyDatabaseConfig(t *testing.T) {
	dir := t.TempDir()
	passwordPath := filepath.Join(dir, "database-password")
	if err := os.WriteFile(passwordPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "migration.toml")
	content := `[database]
url = "postgres://go_tunnels@db/go_tunnels"
password_file = "` + passwordPath + `"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadDatabase(configPath)
	if err != nil {
		t.Fatalf("LoadDatabase() error = %v", err)
	}
	if cfg.URL != "postgres://go_tunnels@db/go_tunnels" || cfg.Password != "secret" {
		t.Fatalf("database config = %#v", cfg)
	}
}

func TestControlValidationRejectsUnsafeAuthenticationSettings(t *testing.T) {
	valid := Control{Server: Server{ListenAddress: ":8080", PublicURL: "https://tunnel.example.com"}, Database: Database{URL: "postgres://db/tunnel"}, Auth: Auth{RPID: "tunnel.example.com", RPOrigin: "https://tunnel.example.com", SessionSigningKey: "01234567890123456789012345678901", CeremonyEncryptionKey: "abcdefghijklmnopqrstuvwxyzABCDEF", SessionTTL: "12h", CeremonyTTL: "5m"}, Relay: Relay{PublicURL: "wss://relay.example.com", TicketKey: "01234567890123456789012345678901", TicketTTL: "5m"}, Security: ControlSecurity{RootPublicKeyFile: "/run/secrets/root_public_key"}}
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

func TestControlValidationRequiresTrustedRootPublicKey(t *testing.T) {
	cfg := Control{Server: Server{ListenAddress: ":8080", PublicURL: "https://tunnel.example.com"}, Database: Database{URL: "postgres://db/tunnel"}, Auth: Auth{RPID: "tunnel.example.com", RPOrigin: "https://tunnel.example.com", SessionSigningKey: "01234567890123456789012345678901", CeremonyEncryptionKey: "abcdefghijklmnopqrstuvwxyzABCDEF", SessionTTL: "12h", CeremonyTTL: "5m"}, Relay: Relay{PublicURL: "wss://relay.example.com", TicketKey: "01234567890123456789012345678901", TicketTTL: "5m"}}
	if err := cfg.validate(); err == nil {
		t.Fatal("validate() accepted control configuration without trusted root public key")
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

func TestLoadRelayServerEnvironmentSecretOverridesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte("[server]\nlisten_address = \"127.0.0.1:0\"\n[security]\nticket_key_file = \"/missing/relay-ticket\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_TUNNELS_RELAY_TICKET_KEY", "01234567890123456789012345678901")
	t.Setenv("GO_TUNNELS_RELAY_UDP_LISTEN_ADDRESS", "127.0.0.1:0")
	cfg, err := LoadRelayServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.TicketKey != "01234567890123456789012345678901" || cfg.Server.UDPListenAddress != "127.0.0.1:0" {
		t.Fatalf("config=%#v", cfg)
	}
}

func TestLoadClientReadsTOMLAndFileReferences(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "enrollment-token")
	ticketPath := filepath.Join(dir, "relay-ticket")
	if err := os.WriteFile(tokenPath, []byte("invite-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ticketPath, []byte("relay-ticket\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "client.toml")
	content := `[node]
state_path = "state/custom-client.json"
control_url = "https://control.example"
enrollment_token_file = "` + tokenPath + `"
name = "travel-client"
[relay]
websocket_url = "wss://relay.example/relay/v1"
udp_address = "relay.example:51820"
ticket_file = "` + ticketPath + `"
destination_device_id = "gateway"
stun_server = "stun:stun.example:3478"
[wireguard]
interface = "wg0"
listen_port = 51830
[coordination]
url = "wss://control.example/api/v1/coordination"
root_public_key_file = "state/root.pub"
[direct]
candidates = "203.0.113.2:51820"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadClient(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.StatePath != "state/custom-client.json" || cfg.Identity.Token != "invite-token" || cfg.Relay.Ticket != "relay-ticket" || cfg.WireGuard.ListenPort != 51830 || cfg.Direct.Candidates != "203.0.113.2:51820" {
		t.Fatalf("unexpected client config: %#v", cfg)
	}
}

func TestLoadAgentAppliesSafeDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.toml")
	if err := os.WriteFile(path, []byte("[node]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.Name != "linux-gateway" || cfg.Identity.StatePath != "state/agent.json" || cfg.Relay.ListenAddress != "127.0.0.1:51821" || cfg.Relay.WireGuardAddress != "127.0.0.1:51820" || cfg.WireGuard.ListenPort != 51820 || cfg.Coordination.NetworkID != "home" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
}

func TestLoadAdminReadsDefaultsAndPassphraseFile(t *testing.T) {
	dir := t.TempDir()
	passphrasePath := filepath.Join(dir, "root-passphrase")
	if err := os.WriteFile(passphrasePath, []byte("correct horse battery staple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "admin.toml")
	content := `endpoint = "https://control.example"
key_id = "root-2026"
root_key_file = "state/root-key.age"
passphrase_file = "` + passphrasePath + `"
network_id = "home"
profile_id = "family"
base_url = "https://control.example/invite"
overlay_pool = "10.200.0.0/24"
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAdmin(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "https://control.example" || cfg.KeyID != "root-2026" || cfg.Passphrase != "correct horse battery staple" || cfg.OverlayPool != "10.200.0.0/24" {
		t.Fatalf("unexpected admin config: %#v", cfg)
	}
}
