package node

import (
	"bytes"
	"context"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
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
		{"relay pair", func(c *config.Node) { c.Relay.WebSocketURL = "wss://relay.localhost/relay/udp/v2" }},
		{"candidates", func(c *config.Node) { c.Direct.Candidates = "not-an-endpoint" }},
		{"routes", func(c *config.Node) { c.WireGuard.Routes = "not-a-prefix" }},
		{"control URL", func(c *config.Node) { c.Identity.ControlURL = ":invalid" }},
		{"signed trust", func(c *config.Node) { c.WireGuard.InterfaceName = "wg-test" }},
		{"relay listen", func(c *config.Node) {
			c.Relay.WebSocketURL = "wss://relay.localhost/relay/udp/v2"
			c.Relay.SessionID = "test-pair"
			c.Relay.DestinationDevice = "test-peer"
			c.Relay.ListenAddress = ""
		}},
		{"insecure v2", func(c *config.Node) {
			c.Relay.WebSocketURL = "ws://relay.localhost/relay/udp/v2"
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
			cfg.Relay.WebSocketURL = "wss://relay.localhost/relay/udp/v2"
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
	app.workers = []lifecycle.Worker{{Name: "cleanup", Component: lifecycle.Func(func(ctx context.Context) error { close(started); <-ctx.Done(); close(cleanup); <-release; return nil })}}
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
