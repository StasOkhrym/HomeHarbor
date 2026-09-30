package main

import "testing"

func TestRelayTLSRequiresBothCertificateAndKeyFiles(t *testing.T) {
	for _, paths := range [][2]string{{"", ""}, {"cert.pem", ""}, {"", "key.pem"}, {"missing-cert.pem", "missing-key.pem"}} {
		if _, err := relayTLSConfig(paths[0], paths[1]); err == nil {
			t.Fatalf("relay accepted invalid TLS files: %v", paths)
		}
	}
}
