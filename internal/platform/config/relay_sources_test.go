package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func relayConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")

	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestRelayRejectsUnknownTOMLKey(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
udp_listen_adress = ":51820"
[security]
ticket_key = "01234567890123456789012345678901"
`)

	_, err := LoadRelayServer(Sources{File: path})

	if err == nil || !strings.Contains(err.Error(), "server.udp_listen_adress") {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestRelayRejectsInlineAndFileKeyInOneSource(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
[security]
ticket_key = "01234567890123456789012345678901"
ticket_key_file = "/definitely/missing/relay-key"
`)

	_, err := LoadRelayServer(Sources{File: path})

	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("same-source secret conflict error = %v", err)
	}
}

func TestRelayPresentEmptyEnvironmentDoesNotFallBack(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
[security]
ticket_key = "01234567890123456789012345678901"
`)
	t.Setenv("HOMEHARBOR_RELAY_TICKET_KEY", "")

	_, err := LoadRelayServer(Sources{File: path})

	if err == nil || !strings.Contains(err.Error(), "ticket key") {
		t.Fatalf("present empty key error = %v", err)
	}
}

func TestRelaySourcePrecedencePreservesChangedZeroAndEmpty(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
udp_listen_address = ":51820"
udp_port_min = 51820
udp_port_max = 51851
udp_advertise_host = "file.example"
[security]
ticket_key = "01234567890123456789012345678901"
tls_cert_file = "file-cert.pem"
tls_key_file = "file-key.pem"
`)
	env := map[string]string{
		"HOMEHARBOR_RELAY_LISTEN_ADDRESS":     "127.0.0.1:8082",
		"HOMEHARBOR_RELAY_UDP_ADVERTISE_HOST": "env.example",
		"HOMEHARBOR_RELAY_TLS_CERT_FILE":      "env-cert.pem",
		"HOMEHARBOR_RELAY_TLS_KEY_FILE":       "env-key.pem",
	}

	cfg, err := LoadRelayServer(Sources{
		File: path,
		Env: func(name string) (string, bool) {
			value, ok := env[name]
			return value, ok
		},
		Flags: map[string]string{
			"server.listen_address":     "127.0.0.1:8083",
			"server.udp_port_min":       "0",
			"server.udp_port_max":       "0",
			"server.udp_advertise_host": "",
			"security.tls_cert_file":    "",
			"security.tls_key_file":     "",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.ListenAddress != "127.0.0.1:8083" ||
		cfg.Server.UDPPortMin != 0 || cfg.Server.UDPPortMax != 0 ||
		cfg.Server.UDPAdvertiseHost != "" ||
		cfg.Security.TLSCertFile != "" || cfg.Security.TLSKeyFile != "" {
		t.Fatalf("final relay config = %#v", cfg)
	}
}

func TestRelayFinalInlineKeySkipsLowerPriorityMissingFile(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
[security]
ticket_key_file = "/definitely/missing/relay-key"
`)
	const key = "01234567890123456789012345678901"

	cfg, err := LoadRelayServer(Sources{
		File: path,
		Env: func(name string) (string, bool) {
			return key, name == "HOMEHARBOR_RELAY_TICKET_KEY"
		},
	})

	if err != nil || cfg.Security.TicketKey != key {
		t.Fatalf("winning inline key = %q, error = %v", cfg.Security.TicketKey, err)
	}
}

func TestRelayFinalFileKeyOverridesLowerInlineKey(t *testing.T) {
	const finalKey = "abcdefghijklmnopqrstuvwxyzABCDEF"
	keyPath := filepath.Join(t.TempDir(), "relay-key")

	if err := os.WriteFile(keyPath, []byte(finalKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	path := relayConfigFile(t, `[server]
listen_address = ":8081"
[security]
ticket_key = "01234567890123456789012345678901"
`)

	cfg, err := LoadRelayServer(Sources{
		File: path,
		Flags: map[string]string{
			"security.ticket_key_file": keyPath,
		},
	})

	if err != nil || cfg.Security.TicketKey != finalKey {
		t.Fatalf("winning file key = %q, error = %v", cfg.Security.TicketKey, err)
	}
}

func TestRelayRejectsSameSourceFlagSecretConflict(t *testing.T) {
	path := relayConfigFile(t, "[server]\nlisten_address = ':8081'\n")

	_, err := LoadRelayServer(Sources{File: path, Flags: map[string]string{
		"security.ticket_key":      "01234567890123456789012345678901",
		"security.ticket_key_file": "/definitely/missing/relay-key",
	}})

	if err == nil || !strings.Contains(err.Error(), "conflict") {
		t.Fatalf("same-source flag conflict error = %v", err)
	}
}

func TestRelayExplicitEmptyUDPListenAddressFailsValidation(t *testing.T) {
	path := relayConfigFile(t, `[server]
listen_address = ":8081"
udp_listen_address = ":51820"
[security]
ticket_key = "01234567890123456789012345678901"
`)

	_, err := LoadRelayServer(Sources{File: path, Flags: map[string]string{
		"server.udp_listen_address": "",
	}})

	if err == nil || !strings.Contains(err.Error(), "udp_listen_address") {
		t.Fatalf("explicit empty UDP address error = %v", err)
	}
}

func TestRelayEnvironmentErrorsAreDeterministic(t *testing.T) {
	path := relayConfigFile(t, "[server]\nlisten_address = ':8081'\n")
	env := map[string]string{
		"HOMEHARBOR_RELAY_UDP_PORT_MIN": "invalid",
		"HOMEHARBOR_RELAY_UDP_PORT_MAX": "invalid",
	}
	for range 32 {
		_, err := LoadRelayServer(Sources{File: path, Env: func(name string) (string, bool) {
			value, ok := env[name]
			return value, ok
		}})

		if err == nil || !strings.Contains(err.Error(), "server.udp_port_max") {
			t.Fatalf("nondeterministic first invalid field: %v", err)
		}
	}
}

func TestRelayFlagErrorsAreDeterministic(t *testing.T) {
	path := relayConfigFile(t, "[server]\nlisten_address = ':8081'\n")
	for range 32 {
		_, err := LoadRelayServer(Sources{File: path, Flags: map[string]string{
			"server.udp_port_min": "invalid",
			"server.udp_port_max": "invalid",
		}})

		if err == nil || !strings.Contains(err.Error(), "server.udp_port_max") {
			t.Fatalf("nondeterministic first invalid flag: %v", err)
		}
	}
}
