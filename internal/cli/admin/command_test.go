package admin

import (
	"bytes"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
)

func TestAdminRemoteAcceptsExplicitCAFlag(t *testing.T) {
	var out, errOut bytes.Buffer

	status := host.Execute(context.Background(), []string{
		"init-snapshot", "--ca-file", "sandbox-ca.pem",
	}, &out, &errOut, NewCommand())

	if status != 1 || !strings.Contains(errOut.String(), "manifest is required") {
		t.Fatalf("status=%d stderr=%q", status, errOut.String())
	}
}

func TestAdminRemoteUsesOnlyExplicitCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "sandbox-ca.pem")

	certificate := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw},
	)

	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	approver, closeClient, err := remoteApprover(options{endpoint: server.URL, caFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient()

	response, err := approver.Client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}

	if _, _, err := remoteApprover(
		options{endpoint: "http://control.localhost", caFile: caFile},
	); err == nil {
		t.Fatal("explicit CA accepted a plaintext control endpoint")
	}
}

func TestCanceledInitRootDoesNotCreateKey(t *testing.T) {
	dir := t.TempDir()
	passphrase := filepath.Join(dir, "passphrase")

	if err := os.WriteFile(passphrase, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(dir, "root.age")
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	var out, errOut bytes.Buffer

	status := host.Execute(
		ctx,
		[]string{"init-root", "--passphrase-file", passphrase, "--key", key},
		&out,
		&errOut,
		NewCommand(),
	)

	if status != 130 {
		t.Fatalf("status = %d, stderr = %q", status, errOut.String())
	}

	if _, err := os.Stat(key); !os.IsNotExist(err) {
		t.Fatalf("canceled command created key: %v", err)
	}
}

func TestFreshCommandTreesDoNotShareChangedConfigFlag(t *testing.T) {
	dir := t.TempDir()
	passphrase := filepath.Join(dir, "passphrase")

	if err := os.WriteFile(passphrase, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer

	status := host.Execute(
		context.Background(),
		[]string{
			"init-root",
			"--config",
			"/definitely/missing/admin.toml",
			"--passphrase-file",
			passphrase,
		},
		&out,
		&errOut,
		NewCommand(),
	)

	if status != 1 || !strings.Contains(errOut.String(), "admin.toml") {
		t.Fatalf("first status = %d, stderr = %q", status, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	key := filepath.Join(dir, "root.age")

	status = host.Execute(
		context.Background(),
		[]string{"init-root", "--passphrase-file", passphrase, "--key", key},
		&out,
		&errOut,
		NewCommand(),
	)

	if status != 0 || strings.TrimSpace(out.String()) == "" {
		t.Fatalf(
			"second status = %d, stdout = %q, stderr = %q",
			status,
			out.String(),
			errOut.String(),
		)
	}
}
