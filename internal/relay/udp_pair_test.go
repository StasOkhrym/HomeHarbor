package relay

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPPairDatagramRoundTripAndBounds(t *testing.T) {
	data, err := EncodeUDPPairDatagram("ticket", []byte("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUDPPairDatagram(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Kind != UDPPairKindData || decoded.Ticket != "ticket" || string(decoded.Payload) != "ciphertext" {
		t.Fatalf("decoded=%#v", decoded)
	}
	if _, err := EncodeUDPPairDatagram("", []byte("ciphertext")); err == nil {
		t.Fatal("empty client ticket was accepted")
	}
	if _, err := EncodeUDPPairDatagram("ticket", make([]byte, maxPacketPayload+1)); err == nil {
		t.Fatal("oversized UDP pair payload was accepted")
	}
}

func TestUDPPairRelayForwardsOnlyToBoundPeer(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	issuer := TicketIssuer{Key: key}
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverConn.Close() }()
	server := NewUDPPairRelay(serverConn, issuer)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(ctx) }()

	clientA := mustUDPClient(t)
	defer func() { _ = clientA.Close() }()
	clientB := mustUDPClient(t)
	defer func() { _ = clientB.Close() }()
	serverAddress := serverConn.LocalAddr().(*net.UDPAddr)
	ticketA, err := issuer.IssueForPeer("session", "client", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketB, err := issuer.IssueForPeer("session", "gateway", "client", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sendPairDatagram(t, clientA, serverAddress, ticketA, []byte("register-a"))
	sendPairDatagram(t, clientB, serverAddress, ticketB, []byte("register-b"))
	sendPairDatagram(t, clientA, serverAddress, ticketA, []byte("opaque-wireguard"))

	if err := clientB.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxPacketPayload+128)
	forwarded := readUDPPairFrame(t, clientB, buffer)
	if forwarded.Kind != UDPPairKindData {
		forwarded = readUDPPairFrame(t, clientB, buffer)
	}
	if forwarded.Ticket != "" || string(forwarded.Payload) != "opaque-wireguard" {
		t.Fatalf("forwarded=%#v", forwarded)
	}

	// A valid ticket cannot be used to register a third device in the pair.
	wrongTicket, err := issuer.IssueForPeer("session", "intruder", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clientIntruder := mustUDPClient(t)
	defer func() { _ = clientIntruder.Close() }()
	sendPairDatagram(t, clientIntruder, serverAddress, wrongTicket, []byte("must-not-forward"))
	if err := clientB.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clientB.ReadFromUDP(buffer); err == nil {
		t.Fatal("unbound third peer reached the destination")
	}
	cancel()
	select {
	case <-serverErr:
	case <-time.After(time.Second):
		t.Fatal("UDP relay did not stop")
	}
}

func readUDPPairFrame(t *testing.T, connection *net.UDPConn, buffer []byte) UDPPairDatagram {
	t.Helper()
	n, _, err := connection.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	datagram, err := DecodeUDPPairDatagram(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	return datagram
}

func mustUDPClient(t *testing.T) *net.UDPConn {
	t.Helper()
	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func sendPairDatagram(t *testing.T, connection *net.UDPConn, destination *net.UDPAddr, ticket string, payload []byte) {
	t.Helper()
	data, err := EncodeUDPPairDatagram(ticket, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.WriteToUDP(data, destination); err != nil {
		t.Fatal(err)
	}
}
