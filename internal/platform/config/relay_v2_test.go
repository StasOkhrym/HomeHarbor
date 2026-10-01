package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRelayLoadsTLSAndBoundedUDPRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.toml")
	data := `[server]
listen_address = ":8081"
udp_listen_address = ":51820"
udp_port_min = 51820
udp_port_max = 51851
udp_advertise_host = "relay.example.com"
[security]
ticket_key = "01234567890123456789012345678901"
tls_cert_file = "/run/secrets/relay_tls_cert"
tls_key_file = "/run/secrets/relay_tls_key"
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRelayServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.UDPPortMin != 51820 || cfg.Server.UDPPortMax != 51851 ||
		cfg.Server.UDPAdvertiseHost != "relay.example.com" ||
		cfg.Security.TLSCertFile != "/run/secrets/relay_tls_cert" ||
		cfg.Security.TLSKeyFile != "/run/secrets/relay_tls_key" {
		t.Fatalf("relay configuration lost fields: %#v", cfg)
	}
}
