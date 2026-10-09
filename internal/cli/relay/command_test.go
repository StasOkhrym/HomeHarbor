package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func relayCommandConfig(t *testing.T, certFile, keyFile string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")
	data := `[server]
listen_address = "127.0.0.1:0"
udp_listen_address = "127.0.0.1:0"
udp_port_min = 51820
udp_port_max = 51851
udp_advertise_host = "file.example"
[security]
ticket_key = "01234567890123456789012345678901"
tls_cert_file = "` + certFile + `"
tls_key_file = "` + keyFile + `"
`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func relayCommandCertificate(t *testing.T) (string, string) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certificateDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		publicKey,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	certPath := filepath.Join(t.TempDir(), "relay-cert.pem")
	keyPath := filepath.Join(t.TempDir(), "relay-key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certificateDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

func TestRelayHelpAndVersionDoNotReadConfigTLSOrStart(t *testing.T) {
	for _, arg := range []string{"--help", "--version"} {
		t.Run(arg, func(t *testing.T) {
			started := false
			var out, errOut bytes.Buffer

			code := host.Execute(context.Background(), []string{
				"--config", "/definitely/missing/relay.toml", arg,
			}, &out, &errOut, newCommand(func(context.Context, config.RelayServer, *tls.Config, *slog.Logger) error {
				started = true
				return errors.New("unexpected start")
			}))

			if code != 0 || started || out.Len() == 0 || errOut.Len() != 0 {
				t.Fatalf(
					"exit=%d started=%v stdout=%q stderr=%q",
					code,
					started,
					out.String(),
					errOut.String(),
				)
			}
		})
	}
}

func TestRelayUsageAndTLSErrorsDoNotStart(t *testing.T) {
	path := relayCommandConfig(t, "missing-cert.pem", "missing-key.pem")
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{name: "unknown flag", args: []string{"--unknown"}, want: 2},
		{name: "positional argument", args: []string{"surprise"}, want: 2},
		{name: "missing config", args: []string{"--config", "/definitely/missing/relay.toml"}, want: 1},
		{name: "missing TLS", args: []string{"--config", path}, want: 1},
		{name: "explicit empty TLS flags", args: []string{"--config", path, "--tls-cert=", "--tls-key="}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			started := false
			var out, errOut bytes.Buffer

			code := host.Execute(
				context.Background(),
				tc.args,
				&out,
				&errOut,
				newCommand(
					func(context.Context, config.RelayServer, *tls.Config, *slog.Logger) error {
						started = true
						return nil
					},
				),
			)

			if code != tc.want || started || errOut.Len() == 0 || out.Len() != 0 {
				t.Fatalf(
					"exit=%d started=%v stdout=%q stderr=%q",
					code,
					started,
					out.String(),
					errOut.String(),
				)
			}
		})
	}
}

func TestRelayPassesSelectedConfigTLSAndContextToRuntime(t *testing.T) {
	certPath, keyPath := relayCommandCertificate(t)

	path := relayCommandConfig(t, "ignored-cert.pem", "ignored-key.pem")
	ctx := context.Background()
	called := false
	var out, errOut bytes.Buffer

	code := host.Execute(ctx, []string{
		"--config", path, "--tls-cert", certPath, "--tls-key", keyPath,
		"--udp-port-min", "0", "--udp-port-max", "0", "--udp-advertise-host=",
	}, &out, &errOut, newCommand(func(gotCtx context.Context, cfg config.RelayServer,
		tlsConfig *tls.Config, logger *slog.Logger,
	) error {
		called = true

		if gotCtx != ctx || cfg.Server.UDPPortMin != 0 || cfg.Server.UDPPortMax != 0 ||
			cfg.Server.UDPAdvertiseHost != "" || len(tlsConfig.Certificates) != 1 || logger == nil {
			t.Fatalf("runtime received wrong context/config/TLS/logger: %v %#v %v %v",
				gotCtx, cfg, tlsConfig, logger)
		}

		return errors.New("runtime stopped")
	}))

	if code != 1 || !called || !strings.Contains(errOut.String(), "run relay: runtime stopped") ||
		out.Len() != 0 {
		t.Fatalf(
			"exit=%d called=%v stdout=%q stderr=%q",
			code,
			called,
			out.String(),
			errOut.String(),
		)
	}
}

func TestRelayTicketKeyFileFlagOverridesStaleConfiguredFile(t *testing.T) {
	certPath, keyPath := relayCommandCertificate(t)
	path := filepath.Join(t.TempDir(), "relay.toml")
	data := `[server]
listen_address = "127.0.0.1:0"
udp_listen_address = "127.0.0.1:0"
[security]
ticket_key_file = "/definitely/missing/relay-ticket-key"
tls_cert_file = "` + certPath + `"
tls_key_file = "` + keyPath + `"
`

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	const key = "abcdefghijklmnopqrstuvwxyzABCDEF"
	selected := filepath.Join(t.TempDir(), "selected-key")

	if err := os.WriteFile(selected, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	called := false
	var out, errOut bytes.Buffer

	code := host.Execute(context.Background(), []string{
		"--config", path, "--ticket-key-file", selected,
	}, &out, &errOut, newCommand(func(_ context.Context, cfg config.RelayServer,
		_ *tls.Config, _ *slog.Logger,
	) error {
		called = true

		if cfg.Security.TicketKey != key {
			t.Fatalf("selected key differs from flag file")
		}

		return nil
	}))

	if code != 0 || !called || errOut.Len() != 0 {
		t.Fatalf("exit=%d called=%v stderr=%q", code, called, errOut.String())
	}
}

func TestRelayCancellationAfterRunCannotReportSuccess(t *testing.T) {
	certPath, keyPath := relayCommandCertificate(t)

	path := relayCommandConfig(t, certPath, keyPath)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var out, errOut bytes.Buffer

	code := host.Execute(ctx, []string{"--config", path}, &out, &errOut,
		newCommand(func(context.Context, config.RelayServer, *tls.Config, *slog.Logger) error {
			cancel()
			return nil
		}))

	if code != 130 || !strings.Contains(errOut.String(), context.Canceled.Error()) {
		t.Fatalf("exit=%d stderr=%q", code, errOut.String())
	}
}

func TestRelayCanceledBeforeRunAvoidsConfigAndTLSIO(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	started := false
	var out, errOut bytes.Buffer

	code := host.Execute(ctx, []string{"--config", "/definitely/missing/relay.toml"}, &out, &errOut,
		newCommand(func(context.Context, config.RelayServer, *tls.Config, *slog.Logger) error {
			started = true
			return nil
		}))

	if code != 130 || started || !strings.Contains(errOut.String(), context.Canceled.Error()) {
		t.Fatalf("exit=%d started=%v stderr=%q", code, started, errOut.String())
	}
}

func TestRelayCommandsHaveIndependentFlags(t *testing.T) {
	first, second := NewCommand(), NewCommand()
	if err := first.Flags().Set("config", "first.toml"); err != nil {
		t.Fatal(err)
	}

	if got := second.Flags().Lookup("config").Value.String(); got != "config/relay.toml" {
		t.Fatalf("second command inherited first command flag: %q", got)
	}
}

func TestRelayTLSRequiresCertificateAndKeyFiles(t *testing.T) {
	for _, paths := range [][2]string{{"", ""}, {"cert.pem", ""}, {"", "key.pem"}, {"missing-cert.pem", "missing-key.pem"}} {
		if _, err := relayTLSConfig(paths[0], paths[1]); err == nil {
			t.Fatalf("relay accepted invalid TLS files: %v", paths)
		}
	}
}
