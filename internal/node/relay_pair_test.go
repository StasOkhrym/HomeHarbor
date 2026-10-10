package node

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodepath "github.com/StasOkhrym/homeharbor/internal/node/path"
	"github.com/StasOkhrym/homeharbor/internal/relay"
)

func TestNodeRejectsOldRelayEndpointEvenWithCapability(t *testing.T) {
	cfg := RelayBridgeConfig{
		RelayURL:            "wss://relay.example/relay/udp/v2",
		RelayTransport:      relay.UDPPairProtocol,
		Ticket:              "ticket",
		SessionID:           "s",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress:       "127.0.0.1:0",
		WireGuardAddress:    "127.0.0.1:9",
	}

	if err := validateRelayBridgeConfig(cfg); err == nil {
		t.Fatal("old relay endpoint accepted with current capability")
	}

	cfg.RelayURL = "wss://relay.example/relay/udp"

	if err := validateRelayBridgeConfig(cfg); err != nil {
		t.Fatalf("canonical relay endpoint rejected: %v", err)
	}
}

func freeUDPAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	connection := listenUDP(t)
	address := connection.LocalAddr().(*net.UDPAddr)

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	return address
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

type waitingRelayWorker struct{ started, cancelled, release, finished chan struct{} }

func (w *waitingRelayWorker) Run(ctx context.Context) error {
	close(w.started)
	<-ctx.Done()
	close(w.cancelled)
	<-w.release
	close(w.finished)
	return nil
}

func TestKernelRelayPathOwnerAwaitsCancelledBridge(t *testing.T) {
	w := &waitingRelayWorker{
		started:   make(chan struct{}),
		cancelled: make(chan struct{}),
		release:   make(chan struct{}),
		finished:  make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- runKernelRelayWithPathSelector(ctx, w, KernelRelayConfig{PeerPublicKey: validPeerKey, EndpointUpdater: &endpointRecorder{}, PathSelector: nodepath.NewPathSelector()}, netip.MustParseAddrPort("127.0.0.1:51821"))
	}()
	<-w.started
	cancel()
	<-w.cancelled
	select {
	case <-done:
		close(w.release)

		t.Fatal("path owner returned while forwarding worker still owned resources")
	case <-time.After(20 * time.Millisecond):
	}

	close(w.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("owner did not await bridge")
	}

	select {
	case <-w.finished:
	default:
		t.Fatal("bridge not finished")
	}
}

func TestNodeUDPPairLoopPreservesSocketDuringRenewalAndControlFailure(t *testing.T) {
	i := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	r, err := relay.NewUDPPair(
		i,
		relay.UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1"), MaxPeersPerDevice: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	s := httptest.NewTLSServer(r)
	defer func() { s.Close() }()

	wg := listenUDP(t)

	local := freeUDPAddress(t)

	ticket, _ := i.IssueForPeer("s", "a", "b", time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	observed := make(chan netip.AddrPort, 16)
	var calls atomic.Int32
	var outage atomic.Bool
	provider := func(context.Context) (string, error) {
		calls.Add(1)
		if outage.Load() {
			return "", errors.New("control unavailable")
		}

		return i.IssueForPeer("s", "a", "b", time.Minute)
	}
	cfg := RelayBridgeConfig{
		RelayTransport:      relay.UDPPairProtocol,
		RelayURL:            "wss" + strings.TrimPrefix(s.URL, "https") + "/relay/udp",
		RelayHTTPClient:     s.Client(),
		Ticket:              ticket,
		TicketLifetime:      80 * time.Millisecond,
		SessionID:           "s",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress:       local.String(),
		WireGuardAddress:    wg.LocalAddr().String(),
		OnObservedEndpoint:  func(a netip.AddrPort) { observed <- a },
	}
	done := make(chan error, 1)
	go func() { done <- RunRelayBridgeLoop(ctx, cfg, provider) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("node relay owner leaked")
		}
	})
	var first netip.AddrPort
	select {
	case first = <-observed:
	case <-time.After(2 * time.Second):
		t.Fatal("node UDP pair did not bind")
	}

	select {
	case second := <-observed:
		if first != second {
			t.Fatal("renewal replaced local socket")
		}
	case <-time.After(time.Second):
		t.Fatal("node did not renew")
	}

	outage.Store(true)
	before := calls.Load()
	deadline := time.Now().Add(time.Second)
	for calls.Load() <= before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if calls.Load() <= before {
		t.Fatal("renewal provider not retried")
	}

	// Active packet-plane ownership must not release the fixed local endpoint
	// simply because the ticket provider cannot contact control.
	u, err := net.ListenUDP("udp", local)
	if err == nil {
		_ = u.Close()

		t.Fatal("control outage released active local socket")
	}
}
