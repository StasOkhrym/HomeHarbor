package relay

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/platform/config"
)

func TestRelayReadinessFollowsUDPListenerLifecycle(t *testing.T) {
	cfg := config.RelayServer{}
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.UDPListenAddress = "127.0.0.1:0"
	cfg.Security.TicketKey = "01234567890123456789012345678901"
	app := New(cfg, slog.Default())
	if status := readinessStatus(app); status != http.StatusServiceUnavailable {
		t.Fatalf("initial readiness status=%d, want %d", status, http.StatusServiceUnavailable)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- app.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && readinessStatus(app) != http.StatusOK {
		time.Sleep(10 * time.Millisecond)
	}
	if status := readinessStatus(app); status != http.StatusOK {
		t.Fatalf("running readiness status=%d, want %d", status, http.StatusOK)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not stop after cancellation")
	}
	if status := readinessStatus(app); status != http.StatusServiceUnavailable {
		t.Fatalf("stopped readiness status=%d, want %d", status, http.StatusServiceUnavailable)
	}
}

func TestRelayReadinessStaysFalseWhenUDPBindFails(t *testing.T) {
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := config.RelayServer{}
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.UDPListenAddress = occupied.LocalAddr().String()
	cfg.Security.TicketKey = "01234567890123456789012345678901"
	app := New(cfg, slog.Default())
	err = app.Run(context.Background())
	if err == nil {
		t.Fatal("Run() error=nil, want UDP bind failure")
	}
	if status := readinessStatus(app); status != http.StatusServiceUnavailable {
		t.Fatalf("failed startup readiness status=%d, want %d", status, http.StatusServiceUnavailable)
	}
}

func readinessStatus(app *App) int {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	app.server.Handler.ServeHTTP(recorder, request)
	return recorder.Code
}
