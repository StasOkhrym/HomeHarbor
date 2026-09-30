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
	relayruntime "github.com/sokhrym/go-tunnels/internal/relay"
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

func TestRelayAppDoesNotExposeLegacyUDPTicketIngress(t *testing.T) {
	cfg := config.RelayServer{}
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.UDPListenAddress = "127.0.0.1:0"
	cfg.Security.TicketKey = "01234567890123456789012345678901"
	a := New(cfg, nil)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	address := udp.LocalAddr().(*net.UDPAddr)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.runWithListeners(ctx, tcp, udp) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("relay shutdown timeout")
		}
	})
	sender, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sender.Close() }()
	ticket, _ := a.tickets.IssueForPeer("s", "a", "b", time.Minute)
	packet, _ := relayruntime.EncodeUDPPairDatagram(ticket, []byte("legacy"))
	if _, err := sender.WriteToUDP(packet, address); err != nil {
		t.Fatal(err)
	}
	_ = sender.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := sender.ReadFromUDP(make([]byte, 512)); err == nil {
		t.Fatal("production app admitted a UDP v1 bearer packet")
	}
	request := httptest.NewRequest(http.MethodGet, "/relay/udp/v2", nil)
	recorder := httptest.NewRecorder()
	a.server.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUpgradeRequired {
		t.Fatalf("v2 plaintext status=%d, want TLS requirement", recorder.Code)
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

func TestRelayExplicitRangeSelectsStartupPort(t *testing.T) {
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	cfg := config.RelayServer{}
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.UDPListenAddress = "127.0.0.1:0"
	cfg.Security.TicketKey = "01234567890123456789012345678901"
	a := NewWithOptions(cfg, nil, Options{UDPV2: relayruntime.UDPPairV2Config{PortMin: port, PortMax: port}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("relay did not stop")
		}
	})
	deadline := time.Now().Add(time.Second)
	for readinessStatus(a) != http.StatusOK && time.Now().Before(deadline) {
		select {
		case err := <-done:
			done <- err
			t.Fatalf("explicit-range startup failed: %v", err)
		default:
		}
		time.Sleep(time.Millisecond)
	}
	if readinessStatus(a) != http.StatusOK {
		t.Fatal("configured range never became ready")
	}
	occupied, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err == nil {
		_ = occupied.Close()
		t.Fatal("readiness did not own a socket in the configured range")
	}
}

func readinessStatus(app *App) int {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	app.server.Handler.ServeHTTP(recorder, request)
	return recorder.Code
}
