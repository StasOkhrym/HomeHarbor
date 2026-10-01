package relay

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBridgeForwardsOpaqueDatagramsBothDirections(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	issuer := TicketIssuer{Key: key}
	hub := NewHub()
	server := httptest.NewServer(WebSocketHandler{Hub: hub, Tickets: issuer})
	defer server.Close()
	relayURL := "ws" + server.URL[len("http"):]

	wireGuardA := mustUDP(t)
	defer func() { _ = wireGuardA.Close() }()
	wireGuardB := mustUDP(t)
	defer func() { _ = wireGuardB.Close() }()
	ticketA, err := issuer.Issue("session", "a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketB, err := issuer.Issue("session", "b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bridgeA, err := NewBridge(BridgeConfig{
		RelayURL:            relayURL,
		Ticket:              ticketA,
		SessionID:           "session",
		DeviceID:            "a",
		DestinationDeviceID: "b",
		ListenAddress: &net.UDPAddr{
			IP: net.IPv4(127, 0, 0, 1),
		},
		WireGuardAddress: wireGuardA.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	bridgeB, err := NewBridge(BridgeConfig{
		RelayURL:            relayURL,
		Ticket:              ticketB,
		SessionID:           "session",
		DeviceID:            "b",
		DestinationDeviceID: "a",
		ListenAddress: &net.UDPAddr{
			IP: net.IPv4(127, 0, 0, 1),
		},
		WireGuardAddress: wireGuardB.LocalAddr().(*net.UDPAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	bridges := []*Bridge{bridgeA, bridgeB}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, bridge := range bridges {
		go func(bridge *Bridge) { _ = bridge.Run(ctx) }(bridge)
	}
	waitForBridge(t, bridgeA, bridgeB)

	bridgeAAddr := bridgeA.LocalAddr()
	if _, err = wireGuardA.WriteToUDP([]byte("a-to-b"), &bridgeAAddr); err != nil {
		t.Fatal(err)
	}
	assertDatagram(t, wireGuardB, "a-to-b")
	bridgeBAddr := bridgeB.LocalAddr()
	if _, err = wireGuardB.WriteToUDP([]byte("b-to-a"), &bridgeBAddr); err != nil {
		t.Fatal(err)
	}
	assertDatagram(t, wireGuardA, "b-to-a")
}

func mustUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func waitForBridge(t *testing.T, bridges ...*Bridge) {
	t.Helper()
	for _, bridge := range bridges {
		select {
		case <-bridge.Connected():
		case <-time.After(2 * time.Second):
			t.Fatal("relay bridge did not connect")
		}
	}
}

func assertDatagram(t *testing.T, connection *net.UDPConn, want string) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	n, _, err := connection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != want {
		t.Fatalf("datagram=%q, want %q", got, want)
	}
}

func TestBridgeRejectsInvalidRelayURL(t *testing.T) {
	if _, err := NewBridge(BridgeConfig{}); err == nil {
		t.Fatal("NewBridge() error=nil")
	}
}

func TestTicketBoundDestinationCannotBeChangedByPacket(t *testing.T) {
	claims := TicketClaims{SessionID: "session", DeviceID: "client", DestinationDeviceID: "gateway"}
	if destinationAllowedByTicket(
		claims,
		Packet{
			SessionID:           "session",
			SourceDeviceID:      "client",
			DestinationDeviceID: "other-device",
			Payload:             []byte("ciphertext"),
		},
	) {
		t.Fatal("ticket-bound packet was allowed to target a different device")
	}
	if !destinationAllowedByTicket(
		claims,
		Packet{
			SessionID:           "session",
			SourceDeviceID:      "client",
			DestinationDeviceID: "gateway",
			Payload:             []byte("ciphertext"),
		},
	) {
		t.Fatal("ticket-bound packet for its authorized peer was rejected")
	}
}
