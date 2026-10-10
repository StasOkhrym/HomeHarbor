package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodedomain "github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func runtimeFixture(t *testing.T) (config.Node, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")
	cfg.Identity.ControlURL = server.URL
	cfg.Identity.Token = "test-enrollment"

	return cfg, calls
}

func assertNoStartupEffects(t *testing.T, cfg config.Node, calls *atomic.Int32) {
	t.Helper()

	if _, err := os.Stat(cfg.Identity.StatePath); !os.IsNotExist(err) {
		t.Errorf("startup wrote identity: %v", err)
	}

	if calls.Load() != 0 {
		t.Errorf("startup contacted control %d times", calls.Load())
	}
}

func TestInvalidRuntimeDoesNotCreateIdentityOrEnroll(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*config.Node)
	}{
		{"relay pair", func(c *config.Node) { c.Relay.WebSocketURL = "wss://relay.localhost/relay/udp" }},
		{"candidates", func(c *config.Node) { c.Direct.Candidates = "not-an-endpoint" }},
		{"routes", func(c *config.Node) { c.WireGuard.Routes = "not-a-prefix" }},
		{"control URL", func(c *config.Node) { c.Identity.ControlURL = ":invalid" }},
		{"signed trust", func(c *config.Node) { c.WireGuard.InterfaceName = "wg-test" }},
		{"relay listen", func(c *config.Node) {
			c.Relay.WebSocketURL = "wss://relay.localhost/relay/udp"
			c.Relay.SessionID = "test-pair"
			c.Relay.DestinationDevice = "test-peer"
			c.Relay.ListenAddress = ""
		}},
		{"insecure relay", func(c *config.Node) {
			c.Relay.WebSocketURL = "ws://relay.localhost/relay/udp"
			c.Relay.SessionID = "test-pair"
			c.Relay.DestinationDevice = "test-peer"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, calls := runtimeFixture(t)
			test.mutate(&cfg)
			app, err := NewRuntime(context.Background(), Client, cfg)
			if err == nil || app != nil {
				t.Fatal("invalid configuration accepted")
			}
			assertNoStartupEffects(t, cfg, calls)
		})
	}
}

func TestNewRuntimeDoesNotStartEnrollment(t *testing.T) {
	cfg, calls := runtimeFixture(t)
	if _, err := NewRuntime(context.Background(), Client, cfg); err != nil {
		t.Fatal(err)
	}

	assertNoStartupEffects(t, cfg, calls)
}

func TestWhitespaceRelaySessionDoesNotCreateIdentityOrEnroll(t *testing.T) {
	for _, sessionID := range []string{" ", "\t\n"} {
		t.Run(sessionID, func(t *testing.T) {
			cfg, calls := runtimeFixture(t)
			cfg.Relay.WebSocketURL = "wss://relay.localhost/relay/udp"
			cfg.Relay.SessionID = sessionID
			cfg.Relay.DestinationDevice = "test-peer"

			app, err := NewRuntime(context.Background(), Client, cfg)

			if err == nil || app != nil {
				t.Error("whitespace relay session accepted before enrollment")
			}

			assertNoStartupEffects(t, cfg, calls)
		})
	}
}

func TestCanceledRunDoesNotStartRuntime(t *testing.T) {
	cfg, calls := runtimeFixture(t)
	app, err := NewRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	cancel()

	if err := app.Run(ctx); err != nil {
		t.Fatal(err)
	}

	assertNoStartupEffects(t, cfg, calls)
}

func TestRuntimeRestartPreservesIdentityBytes(t *testing.T) {
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")
	var before []byte
	for i := range 2 {
		app, err := NewRuntime(context.Background(), Client, cfg)
		if err != nil {
			t.Fatal(err)
		}

		if err := app.Run(context.Background()); err != nil {
			t.Fatal(err)
		}

		after, err := os.ReadFile(cfg.Identity.StatePath)
		if err != nil {
			t.Fatal(err)
		}

		if i != 0 && !bytes.Equal(before, after) {
			t.Fatal("restart replaced the persisted identity")
		}

		before = after
	}
}

func TestRuntimeHoldsStateOwnerUntilWorkersStop(t *testing.T) {
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")

	first, err := startRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatal(err)
	}

	second, err := startRuntime(context.Background(), Client, cfg)
	if err == nil {
		_ = second.Run(context.Background())

		t.Error("second runtime acquired same identity")
	}

	if err := first.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	third, err := startRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatalf("owner was not released: %v", err)
	}

	if err := third.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStartupFailureReleasesStateOwner(t *testing.T) {
	cfg, _ := runtimeFixture(t)

	if _, err := startRuntime(context.Background(), Client, cfg); err == nil {
		t.Fatal("enrollment unexpectedly succeeded")
	}

	store, err := localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		t.Fatalf("failed startup retained state owner: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRetainsStateOwnerDuringWorkerCleanup(t *testing.T) {
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")

	app, err := startRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := make(chan struct{})
	release := make(chan struct{})
	started := make(chan struct{})
	defer close(release)

	app.workers = []lifecycle.Worker{
		{
			Name: "cleanup",
			Component: lifecycle.Func(
				func(ctx context.Context) error { close(started); <-ctx.Done(); close(cleanup); <-release; return nil },
			),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stopped := make(chan error, 1)
	go func() { stopped <- app.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}

	cancel()
	select {
	case <-cleanup:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter cleanup")
	}

	store, err := localstate.Open(cfg.Identity.StatePath)
	if err == nil {
		_ = store.Close()

		t.Fatal("state owner released before worker cleanup")
	}

	release <- struct{}{}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not stop")
	}

	store, err = localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		t.Fatalf("runtime did not release state: %v", err)
	}

	_ = store.Close()
}

// The command boundary is faked because these tests must never change host
// firewall state. Enrollment, renewal, relay admission and local state are real.
func guardedRuntimeFixture(t *testing.T) (config.Node, string) {
	t.Helper()
	cfg := config.DefaultClient()
	dir := t.TempDir()
	cfg.Identity.StatePath = filepath.Join(dir, "state.json")
	cfg.Identity.Token = "test-enrollment"
	cfg.WireGuard.InterfaceName = "hh-test"
	cfg.Coordination.URL = "ws://127.0.0.1:1/coordination"
	cfg.Coordination.NetworkID = "test-network"
	cfg.Coordination.RootPublicKeyFile = filepath.Join(dir, "root.pub")

	if err := os.WriteFile(
		cfg.Coordination.RootPublicKeyFile,
		[]byte(base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	guard := filepath.Join(dir, "firewall")
	t.Setenv("HH_TEST_GUARD", guard)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := os.WriteFile(
		filepath.Join(dir, "nft"),
		[]byte(
			"#!/bin/sh\nif [ \"$1\" = list ]; then exit 0; fi\nif [ \"${HH_TEST_GUARD_FAIL:-}\" = yes ]; then exit 1; fi\ncat > \"$HH_TEST_GUARD\"\n",
		),
		0o700,
	); err != nil {
		t.Fatal(err)
	}

	return cfg, guard
}

func assertOwnedDeny(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)

	if err != nil || !bytes.Contains(data, []byte(`iifname "hh-test" drop`)) ||
		!bytes.Contains(data, []byte(`oifname "hh-test" drop`)) ||
		bytes.Contains(data, []byte("dport")) {
		t.Errorf("owned deny missing: %q, %v", data, err)
	}
}

func TestDenyPrecedesEnrollmentAndRelayAdmission(t *testing.T) {
	cfg, guard := guardedRuntimeFixture(t)
	var enrollment, rotation, relay atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertOwnedDeny(t, guard)
		switch r.URL.Path {
		case "/api/v1/enroll":
			enrollment.Add(1)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).
				Encode(protocol.EnrolledDevice{ID: "gateway", Credential: "first", CredentialExpiresAt: time.Now().Add(time.Hour)})
		case "/api/v1/devices/credentials/rotate":
			rotation.Add(1)
			_ = json.NewEncoder(w).
				Encode(protocol.CredentialLease{DeviceID: "gateway", Credential: "renewed", ExpiresAt: time.Now().Add(time.Hour)})
		default:
			relay.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()

	cfg.Identity.ControlURL = server.URL

	state, err := nodedomain.NewState()
	if err != nil {
		t.Fatal(err)
	}

	cfg.WireGuard.PeerPublicKey = state.WireGuard.PublicKey
	cfg.WireGuard.ListenPort = 51820
	cfg.WireGuard.OverlayAddress = "100.64.0.1/32"
	cfg.Relay.WebSocketURL = "wss://127.0.0.1:1/relay/udp"
	cfg.Relay.SessionID = "session"
	cfg.Relay.DestinationDevice = "peer"

	app, err := NewRuntime(context.Background(), Gateway, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("relay admission unexpectedly succeeded")
	}

	if enrollment.Load() != 1 || rotation.Load() != 1 || relay.Load() != 1 {
		t.Fatalf(
			"missing admission coverage: enroll=%d rotate=%d relay=%d",
			enrollment.Load(),
			rotation.Load(),
			relay.Load(),
		)
	}
}

func TestAdmissionFailureLeavesOwnedDeny(t *testing.T) {
	cfg, guard := guardedRuntimeFixture(t)

	if err := os.WriteFile(guard, []byte("retained allow"), 0o600); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		),
	)
	defer server.Close()

	cfg.Identity.ControlURL = server.URL

	app, err := NewRuntime(context.Background(), Gateway, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("enrollment unexpectedly succeeded")
	}

	assertOwnedDeny(t, guard)

	store, err := localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFailedRuntimeGuardPreventsIdentityAndAdmission(t *testing.T) {
	cfg, _ := guardedRuntimeFixture(t)
	t.Setenv("HH_TEST_GUARD_FAIL", "yes")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cfg.Identity.ControlURL = server.URL

	app, err := NewRuntime(context.Background(), Gateway, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("failed guard accepted")
	}

	assertNoStartupEffects(t, cfg, &calls)
}

func TestClientRuntimeNeverInstallsForwardingGuard(t *testing.T) {
	cfg, guard := guardedRuntimeFixture(t)
	server := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		),
	)
	defer server.Close()

	cfg.Identity.ControlURL = server.URL

	app, err := NewRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("enrollment unexpectedly succeeded")
	}

	if _, err := os.Stat(guard); !os.IsNotExist(err) {
		t.Fatalf("client touched firewall: %v", err)
	}
}

func TestOrderlyGatewayStopLeavesDenyAndReportsCleanupFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			cfg, guard := guardedRuntimeFixture(t)
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v1/enroll" {
						w.WriteHeader(http.StatusCreated)
						_ = json.NewEncoder(w).
							Encode(protocol.EnrolledDevice{ID: "gateway", Credential: "first", CredentialExpiresAt: time.Now().Add(time.Hour)})

						return
					}

					_ = json.NewEncoder(w).
						Encode(protocol.CredentialLease{DeviceID: "gateway", Credential: "renewed", ExpiresAt: time.Now().Add(time.Hour)})
				}),
			)
			defer server.Close()

			cfg.Identity.ControlURL = server.URL

			app, err := startRuntime(context.Background(), Gateway, cfg)
			if err != nil {
				t.Fatal(err)
			}

			workerErr := errors.New("worker stopped")
			app.workers = []lifecycle.Worker{
				{Name: "fixture", Component: lifecycle.Func(func(context.Context) error {
					// Simulate the last signed policy apply; cleanup must replace this
					// only after this worker has finished its last mutation.
					if err := os.WriteFile(guard, []byte("retained allow"), 0o600); err != nil {
						return err
					}

					if fail {
						t.Setenv("HH_TEST_GUARD_FAIL", "yes")
					}

					return workerErr
				})},
			}

			err = app.Run(context.Background())

			if !errors.Is(err, workerErr) {
				t.Fatalf("lost worker failure: %v", err)
			}

			if fail {
				if !strings.Contains(err.Error(), "deny guard") {
					t.Fatalf("lost guard cleanup failure: %v", err)
				}
			} else {
				assertOwnedDeny(t, guard)
			}

			store, err := localstate.Open(cfg.Identity.StatePath)
			if err != nil {
				t.Fatalf("cleanup did not release owner: %v", err)
			}

			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuntimeOwnershipFailureDoesNotReplaceLivePolicy(t *testing.T) {
	cfg, guard := guardedRuntimeFixture(t)

	store, err := localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()

	if err := os.WriteFile(guard, []byte("live owner policy"), 0o600); err != nil {
		t.Fatal(err)
	}

	app, err := NewRuntime(context.Background(), Gateway, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := app.Run(
		context.Background(),
	); err == nil ||
		!strings.Contains(err.Error(), "acquire state lock") {
		t.Fatalf("expected ownership failure: %v", err)
	}

	data, err := os.ReadFile(guard)

	if err != nil || string(data) != "live owner policy" {
		t.Fatalf("competing runtime changed policy: %q %v", data, err)
	}
}

func TestRuntimeRechecksTrustBeforeGuardOrIdentity(t *testing.T) {
	cfg, guard := guardedRuntimeFixture(t)
	app, err := NewRuntime(context.Background(), Gateway, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		cfg.Coordination.RootPublicKeyFile,
		[]byte("invalid"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("changed trust anchor accepted")
	}

	if _, err := os.Stat(guard); !os.IsNotExist(err) {
		t.Fatalf("invalid trust changed firewall: %v", err)
	}

	var calls atomic.Int32

	assertNoStartupEffects(t, cfg, &calls)
}
