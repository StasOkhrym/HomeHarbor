package node

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/relay"
)

type managedEndpointCapture struct {
	bound   chan netip.AddrPort
	cleared chan string
}

func (c *managedEndpointCapture) SetPeerEndpoint(
	_ context.Context,
	_ string,
	address netip.AddrPort,
) error {
	c.bound <- address
	return nil
}

func (c *managedEndpointCapture) ClearPeerEndpoint(_ context.Context, key string) error {
	c.cleared <- key
	return nil
}

func TestSignedRelaySupervisorRealTLSUDPPairEchoAndSignedRemoval(t *testing.T) {
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	server, err := relay.NewUDPPair(issuer, relay.UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()

	tls := httptest.NewTLSServer(server)
	defer tls.Close()

	relayURL := "wss" + strings.TrimPrefix(tls.URL, "https") + "/relay/udp"

	gatewayWG := listenUDP(t)

	clientWG := listenUDP(t)

	cfg, value := signedRelayFixture(t)
	capture := &managedEndpointCapture{
		bound:   make(chan netip.AddrPort, 4),
		cleared: make(chan string, 4),
	}
	cfg.RelayURL = relayURL

	cfg.HTTPClient = tls.Client()

	cfg.WireGuardAddress = gatewayWG.LocalAddr().String()
	cfg.Endpoints = capture
	cfg.Issue = func(_ context.Context, session, destination string) (RelaySession, error) {
		ticket, err := issuer.IssueForPeer(session, cfg.DeviceID, destination, time.Minute)
		return RelaySession{
			SessionID:           session,
			DeviceID:            cfg.DeviceID,
			DestinationDeviceID: destination,
			RelayURL:            relayURL,
			RelayTransport:      protocol.CapabilityUDPPair,
			Ticket:              ticket,
			ExpiresInSeconds:    60,
		}, err
	}

	owner, err := NewSignedRelaySupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- owner.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("managed relay leaked")
		}
	})

	if err := owner.Apply(ctx, value); err != nil {
		t.Fatal(err)
	}

	session, err := protocol.RelayPairSessionID("home", cfg.RootPublicKey, "client", "gateway")
	if err != nil {
		t.Fatal(err)
	}

	ticket, err := issuer.IssueForPeer(session, "client", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := relay.NewUDPPairBridge(relay.UDPPairBridgeConfig{
		ControlURL:               relayURL,
		HTTPClient:               tls.Client(),
		Ticket:                   ticket,
		SessionID:                session,
		DeviceID:                 "client",
		DestinationDeviceID:      "gateway",
		ListenAddress:            &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		WireGuardAddress:         clientWG.LocalAddr().(*net.UDPAddr),
		RejectUnconfirmedSources: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()

	if err := peer.Bind(ctx, ticket); err != nil {
		t.Fatal(err)
	}

	var local netip.AddrPort
	select {
	case local = <-capture.bound:
	case <-ctx.Done():
		t.Fatal("authenticated gateway endpoint missing")
	}

	if !local.Addr().IsLoopback() || local.Port() == 0 {
		t.Fatal("published endpoint is not an owned loopback socket")
	}

	// Unrelated local UDP senders cannot inject into the authenticated path.
	rogue := listenUDP(t)

	if _, err := rogue.WriteToUDPAddrPort([]byte("rogue"), local); err != nil {
		t.Fatal(err)
	}

	observed, ok := peer.ObservedEndpoint()
	if !ok {
		t.Fatal("client return path was not confirmed")
	}

	if _, err := rogue.WriteToUDPAddrPort([]byte("foreign egress sender"), observed); err != nil {
		t.Fatal(err)
	}

	if err := gatewayWG.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 2048)

	if _, _, err := gatewayWG.ReadFromUDP(buffer); err == nil {
		t.Fatal("managed relay accepted an unconfirmed local sender as a direct candidate")
	}

	if err := clientWG.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := clientWG.ReadFromUDP(buffer); err == nil {
		t.Fatal("foreign local sender forwarded")
	}

	if err := clientWG.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	packet := []byte("opaque WireGuard datagram fixture")

	if _, err := gatewayWG.WriteToUDPAddrPort(packet, local); err != nil {
		t.Fatal(err)
	}

	n, _, err := clientWG.ReadFromUDP(buffer)

	if err != nil || !bytes.Equal(buffer[:n], packet) {
		t.Fatalf("gateway packet was not relayed: %v", err)
	}

	reply := []byte("opaque encrypted reply fixture")

	peerLocal := peer.LocalAddr()

	if _, err := clientWG.WriteToUDP(reply, &peerLocal); err != nil {
		t.Fatal(err)
	}

	if err := gatewayWG.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}

	n, _, err = gatewayWG.ReadFromUDP(buffer)

	if err != nil || !bytes.Equal(buffer[:n], reply) {
		t.Fatalf("client reply was not relayed: %v", err)
	}

	removed := cloneNetworkSnapshot(value)
	removed.Revision = 2
	// Local gateway revocation must stop existing ciphertext paths too, even
	// though the relay ticket and the remote client's bridge are still live.
	removed.Devices = removed.Devices[1:]
	removed.Gateways = nil

	if err := owner.Apply(ctx, removed); err != nil {
		t.Fatal(err)
	}

	select {
	case key := <-capture.cleared:
		if key != value.Devices[1].WireGuardPublicKey {
			t.Fatal("wrong endpoint cleared")
		}
	default:
		t.Fatal("removed peer endpoint not cleared before apply returned")
	}

	// Rebinding succeeds only after the owned worker's local socket is joined.
	freed, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
	if err != nil {
		t.Fatal("removed transport socket still owned:", err)
	}

	if err := freed.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := clientWG.WriteToUDP(reply, &peerLocal); err != nil {
		t.Fatal(err)
	}

	if err := gatewayWG.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := gatewayWG.ReadFromUDP(buffer); err == nil {
		t.Fatal("removed relay still forwarded a packet")
	}
}
