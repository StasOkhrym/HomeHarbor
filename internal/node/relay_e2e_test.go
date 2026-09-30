package node

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/relay"
)

func TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections(t *testing.T) {
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	hub := relay.NewHub()
	server := httptest.NewServer(relay.WebSocketHandler{Hub: hub, Tickets: issuer})
	defer server.Close()

	const sessionID = "acceptance-session"
	ticketA, err := issuer.Issue(sessionID, "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketB, err := issuer.Issue(sessionID, "client", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	bridgeListenA := freeUDPAddress(t)
	bridgeListenB := freeUDPAddress(t)
	wireGuardA := listenUDP(t)
	wireGuardB := listenUDP(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridgeURL := "ws" + server.URL[len("http"):]
	errCh := make(chan error, 2)
	go func() {
		errCh <- RunRelayBridge(ctx, RelayBridgeConfig{
			RelayURL:            bridgeURL,
			Ticket:              ticketA,
			SessionID:           sessionID,
			DeviceID:            "gateway",
			DestinationDeviceID: "client",
			ListenAddress:       bridgeListenA.String(),
			WireGuardAddress:    wireGuardA.LocalAddr().String(),
		})
	}()
	go func() {
		errCh <- RunRelayBridge(ctx, RelayBridgeConfig{
			RelayURL:            bridgeURL,
			Ticket:              ticketB,
			SessionID:           sessionID,
			DeviceID:            "client",
			DestinationDeviceID: "gateway",
			ListenAddress:       bridgeListenB.String(),
			WireGuardAddress:    wireGuardB.LocalAddr().String(),
		})
	}()

	payloadA := []byte("encrypted-wireguard-datagram-a")
	waitForUDP(t, wireGuardB, bridgeListenA, payloadA)
	payloadB := []byte("encrypted-wireguard-datagram-b")
	waitForUDP(t, wireGuardA, bridgeListenB, payloadB)

	cancel()
	for range 2 {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("relay bridge exited with error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("relay bridge did not stop after cancellation")
		}
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
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func waitForUDP(t *testing.T, receiver *net.UDPConn, bridgeAddress *net.UDPAddr, want []byte) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buffer := make([]byte, 256)
	for time.Now().Before(deadline) {
		sender, err := net.DialUDP("udp", nil, bridgeAddress)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = sender.Write(want)
		_ = sender.Close()
		_ = receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _, readErr := receiver.ReadFromUDP(buffer)
		if readErr == nil && string(buffer[:n]) == string(want) {
			return
		}
	}
	t.Fatalf("did not receive UDP payload %q", want)
}
