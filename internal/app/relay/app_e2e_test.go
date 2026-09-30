package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/node"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
)

func TestRelayAppBridgesTwoNodesThroughProductionListeners(t *testing.T) {
	cfg := config.RelayServer{}
	cfg.Server.ListenAddress = "127.0.0.1:0"
	cfg.Server.UDPListenAddress = "127.0.0.1:0"
	cfg.Security.TicketKey = "01234567890123456789012345678901"
	app := New(cfg, slog.Default())

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	appErrors := make(chan error, 1)
	go func() { appErrors <- app.runWithListeners(ctx, tcpListener, udpListener) }()

	waitForRelayReady(t, tcpListener.Addr().String())

	const sessionID = "production-relay-acceptance"
	ticketGateway, err := app.tickets.IssueForPeer(sessionID, "gateway", "client", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ticketClient, err := app.tickets.IssueForPeer(sessionID, "client", "gateway", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	bridgeListenGateway := freeRelayUDPAddress(t)
	bridgeListenClient := freeRelayUDPAddress(t)
	wireGuardGateway := listenRelayUDP(t)
	wireGuardClient := listenRelayUDP(t)
	bridgeErrors := make(chan error, 2)
	go func() {
		bridgeErrors <- node.RunRelayBridge(ctx, node.RelayBridgeConfig{
			RelayUDPAddress:     udpListener.LocalAddr().String(),
			Ticket:              ticketGateway,
			SessionID:           sessionID,
			DeviceID:            "gateway",
			DestinationDeviceID: "client",
			ListenAddress:       bridgeListenGateway.String(),
			WireGuardAddress:    wireGuardGateway.LocalAddr().String(),
		})
	}()
	go func() {
		bridgeErrors <- node.RunRelayBridge(ctx, node.RelayBridgeConfig{
			RelayUDPAddress:     udpListener.LocalAddr().String(),
			Ticket:              ticketClient,
			SessionID:           sessionID,
			DeviceID:            "client",
			DestinationDeviceID: "gateway",
			ListenAddress:       bridgeListenClient.String(),
			WireGuardAddress:    wireGuardClient.LocalAddr().String(),
		})
	}()

	// udp_pair_v1 learns the destination only after both authenticated tickets
	// have registered. Prime both bridge sockets before asserting forwarding so
	// the first payload is not mistaken for a one-sided binding probe.
	primeRelayPeer(t, wireGuardGateway, bridgeListenGateway)
	primeRelayPeer(t, wireGuardClient, bridgeListenClient)
	waitForRelayUDP(t, wireGuardGateway, bridgeListenGateway, wireGuardClient, []byte("gateway-to-client"))
	waitForRelayUDP(t, wireGuardClient, bridgeListenClient, wireGuardGateway, []byte("client-to-gateway"))

	cancel()
	for range 2 {
		select {
		case err := <-bridgeErrors:
			if err != nil {
				t.Fatalf("relay bridge exited with error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("relay bridge did not stop after cancellation")
		}
	}
	select {
	case err := <-appErrors:
		if err != nil {
			t.Fatalf("relay app exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay app did not stop after cancellation")
	}
}

func primeRelayPeer(t *testing.T, sender *net.UDPConn, bridgeAddress *net.UDPAddr) {
	t.Helper()
	for index := 0; index < 20; index++ {
		if _, err := sender.WriteToUDP([]byte("register"), bridgeAddress); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForRelayReady(t *testing.T, address string) {
	t.Helper()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://" + address + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("production relay readiness did not become healthy")
}

func waitForRelayUDP(t *testing.T, sender *net.UDPConn, bridgeAddress *net.UDPAddr, receiver *net.UDPConn, payload []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 256)
	for time.Now().Before(deadline) {
		_, _ = sender.WriteToUDP(payload, bridgeAddress)
		_ = receiver.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, _, readErr := receiver.ReadFromUDP(buffer)
		if readErr == nil && string(buffer[:n]) == string(payload) {
			return
		}
	}
	t.Fatalf("did not receive UDP payload %q", payload)
}

func freeRelayUDPAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	connection := listenRelayUDP(t)
	address := connection.LocalAddr().(*net.UDPAddr)

	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}

	return address
}

func listenRelayUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	connection, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = connection.Close() })
	return connection
}
