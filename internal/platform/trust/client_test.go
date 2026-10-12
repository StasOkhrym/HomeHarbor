package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientUsesOnlyExplicitCAAndRejectsRedirect(t *testing.T) {
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer trusted.Close()

	untrusted := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}

	certificate, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}

	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{certificate}, PrivateKey: private,
	}}}

	untrusted.StartTLS()
	defer untrusted.Close()

	path := filepath.Join(t.TempDir(), "ca.pem")

	trustedPEM := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: trusted.Certificate().Raw},
	)

	if err := os.WriteFile(path, trustedPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	client, err := NewHTTPClientFromCAFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	response, err := client.Get(trusted.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()

	if response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("redirect followed: status=%d", response.StatusCode)
	}

	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodGet, untrusted.URL, nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(request)
	if err == nil {
		_ = response.Body.Close()

		t.Fatal("untrusted server was accepted")
	}
}

func TestMalformedCAFailsBeforeNetworkUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")

	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewHTTPClientFromCAFile(path); err == nil {
		t.Fatal("malformed CA accepted")
	}
}
