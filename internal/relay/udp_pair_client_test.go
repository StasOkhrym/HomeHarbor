package relay

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

func TestUDPPairBridgeDiscoversReflexiveEndpointOnOwnedSocket(t *testing.T) {
	stunServer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stunServer.Close() }()
	go func() {
		buffer := make([]byte, 1500)
		n, source, readErr := stunServer.ReadFromUDP(buffer)
		if readErr != nil {
			return
		}
		request := stun.New()
		if stunErr := request.UnmarshalBinary(buffer[:n]); stunErr != nil {
			return
		}
		response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: net.ParseIP("203.0.113.10"), Port: 45678})
		_, _ = stunServer.WriteToUDP(response.Raw, source)
	}()

	bridge, err := NewUDPPairBridge(UDPPairBridgeConfig{
		Ticket:           "ticket",
		RelayAddress:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
		ListenAddress:    &net.UDPAddr{IP: net.ParseIP("127.0.0.1")},
		WireGuardAddress: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bridge.udp.Close() }()
	endpoint, err := bridge.DiscoverServerReflexive(context.Background(), "stun:"+stunServer.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("203.0.113.10:45678"); endpoint != want {
		t.Fatalf("endpoint=%s, want=%s", endpoint, want)
	}
}

func TestUDPPairBridgesForwardOpaquePayloadThroughRelay(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	issuer := TicketIssuer{Key: key}
	serverConnection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverConnection.Close() }()
	relay := NewUDPPairRelay(serverConnection, issuer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = relay.Run(ctx) }()
	relayAddress := serverConnection.LocalAddr().(*net.UDPAddr)

	wireGuardA := mustUDPClient(t)
	defer func() { _ = wireGuardA.Close() }()
	wireGuardB := mustUDPClient(t)
	defer func() { _ = wireGuardB.Close() }()
	ticketA, err := issuer.IssueForPeer("session", "client", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketB, err := issuer.IssueForPeer("session", "gateway", "client", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan netip.AddrPort, 1)
	bridgeA, err := NewUDPPairBridge(UDPPairBridgeConfig{Ticket: ticketA, RelayAddress: relayAddress, ListenAddress: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, WireGuardAddress: wireGuardA.LocalAddr().(*net.UDPAddr), OnObservedEndpoint: func(endpoint netip.AddrPort) { observed <- endpoint }})
	if err != nil {
		t.Fatal(err)
	}
	bridgeB, err := NewUDPPairBridge(UDPPairBridgeConfig{Ticket: ticketB, RelayAddress: relayAddress, ListenAddress: &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}, WireGuardAddress: wireGuardB.LocalAddr().(*net.UDPAddr)})
	if err != nil {
		t.Fatal(err)
	}
	bridgeErrors := make(chan error, 2)
	go func() { bridgeErrors <- bridgeA.Run(ctx) }()
	go func() { bridgeErrors <- bridgeB.Run(ctx) }()
	defer func() {
		cancel()
		_ = bridgeA.udp.Close()
		_ = bridgeB.udp.Close()
	}()

	bridgeAAddress := bridgeA.LocalAddr()
	bridgeBAddress := bridgeB.LocalAddr()
	if _, err := wireGuardA.WriteToUDP([]byte("register-a"), &bridgeAAddress); err != nil {
		t.Fatal(err)
	}
	select {
	case endpoint := <-observed:
		want, parseErr := netip.ParseAddrPort(bridgeAAddress.String())
		if parseErr != nil || endpoint != want {
			t.Fatalf("observed endpoint=%s, want=%s", endpoint, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay binding endpoint was not reported")
	}
	waitForUDPPairPeers(t, relay, "session", 1)
	if _, err := wireGuardB.WriteToUDP([]byte("register"), &bridgeBAddress); err != nil {
		t.Fatal(err)
	}
	waitForUDPPairPeers(t, relay, "session", 2)
	if _, err := wireGuardA.WriteToUDP([]byte("opaque-wireguard"), &bridgeAAddress); err != nil {
		t.Fatal(err)
	}
	if err := wireGuardB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPacketPayload)
	n, _, err := wireGuardB.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "opaque-wireguard" {
		t.Fatalf("payload=%q", buffer[:n])
	}

	directPeer := mustUDPClient(t)
	defer func() { _ = directPeer.Close() }()
	if _, err := directPeer.WriteToUDP([]byte("direct-wireguard"), &bridgeBAddress); err != nil {
		t.Fatal(err)
	}
	if err := wireGuardB.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err = wireGuardB.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if string(buffer[:n]) != "direct-wireguard" {
		t.Fatalf("direct payload=%q", buffer[:n])
	}

	cancel()
	_ = bridgeA.udp.Close()
	_ = bridgeB.udp.Close()
	select {
	case <-bridgeErrors:
	case <-time.After(time.Second):
		t.Fatal("UDP pair bridges did not stop")
	}
}

func TestUDPPairRelayAcceptsAuthenticatedSourceRebinding(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	issuer := TicketIssuer{Key: key}
	relaySocket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = relaySocket.Close() }()
	relay := NewUDPPairRelay(relaySocket, issuer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = relay.Run(ctx) }()

	ticketA, err := issuer.IssueForPeer("roaming", "client", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketB, err := issuer.IssueForPeer("roaming", "gateway", "client", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	peerA := mustUDPClient(t)
	defer func() { _ = peerA.Close() }()
	peerB := mustUDPClient(t)
	defer func() { _ = peerB.Close() }()
	relayAddress := relaySocket.LocalAddr().(*net.UDPAddr)
	register := func(connection *net.UDPConn, ticket string) {
		t.Helper()
		packet, encodeErr := EncodeUDPPairDatagram(ticket, []byte("register"))
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if _, writeErr := connection.WriteToUDP(packet, relayAddress); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	register(peerA, ticketA)
	register(peerB, ticketB)
	waitForUDPPairPeers(t, relay, "roaming", 2)
	readUDPPairKind(t, peerA, UDPPairKindBinding)
	readUDPPairKind(t, peerB, UDPPairKindBinding)

	// A new source socket models a NAT mapping change. The ticket remains
	// bound to the same authenticated device pair, so the relay may replace
	// only that device's observed address and must not create a third peer.
	roamedPeerA := mustUDPClient(t)
	defer func() { _ = roamedPeerA.Close() }()
	packet, err := EncodeUDPPairDatagram(ticketA, []byte("after-roaming"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := roamedPeerA.WriteToUDP(packet, relayAddress); err != nil {
		t.Fatal(err)
	}
	datagram := readUDPPairKind(t, peerB, UDPPairKindData)
	if string(datagram.Payload) != "after-roaming" {
		t.Fatalf("payload after roaming=%q", datagram.Payload)
	}
	relay.mu.Lock()
	got := len(relay.sessions["roaming"])
	relay.mu.Unlock()
	if got != 2 {
		t.Fatalf("roaming peers=%d, want 2", got)
	}
}

func readUDPPairKind(t *testing.T, connection *net.UDPConn, want uint8) UDPPairDatagram {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxUDPPairDatagramSize)
	for {
		n, _, err := connection.ReadFromUDP(buffer)
		if err != nil {
			t.Fatal(err)
		}
		datagram, err := DecodeUDPPairDatagram(buffer[:n])
		if err != nil {
			t.Fatal(err)
		}
		if datagram.Kind == want {
			return datagram
		}
	}
}

func waitForUDPPairPeers(t *testing.T, relay *UDPPairRelay, session string, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		relay.mu.Lock()
		got := len(relay.sessions[session])
		relay.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("UDP pair peers did not register")
}
