package node

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nodedomain "github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/relay"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type signedRuntimeEndpoint struct{ bound chan netip.AddrPort }

func (e signedRuntimeEndpoint) SetPeerEndpoint(
	_ context.Context,
	_ string,
	address netip.AddrPort,
) error {
	e.bound <- address
	return nil
}
func (signedRuntimeEndpoint) ClearPeerEndpoint(context.Context, string) error { return nil }

func TestPreparedSignedGatewayUsesCurrentLeaseAndRealTLSRelayWithoutStaticPair(t *testing.T) {
	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	udp, err := relay.NewUDPPair(issuer, relay.UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = udp.Close() })

	state, err := nodedomain.NewState()
	if err != nil {
		t.Fatal(err)
	}

	state.DeviceID = "gateway"
	state.DeviceRole = "gateway"

	client, err := nodedomain.NewState()
	if err != nil {
		t.Fatal(err)
	}

	rootKey := ed25519.NewKeyFromSeed(make([]byte, 32))
	root := rootKey.Public().(ed25519.PublicKey)

	pair, err := protocol.RelayPairSessionID("home", root, "gateway", "client")
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int32
	var relayURL string
	mux := http.NewServeMux()

	mux.Handle("/relay/udp", udp)
	mux.HandleFunc("/api/v1/relay-sessions", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer current-lease" ||
			r.URL.RawQuery != "" {
			t.Error("managed ticket request lost scoped current lease")

			w.WriteHeader(http.StatusForbidden)
			return
		}

		var request protocol.RelaySessionRequest

		if err := json.NewDecoder(r.Body).
			Decode(&request); err != nil || request.SessionID != pair ||
			request.DestinationDeviceID != "client" {
			t.Error("managed ticket request lost canonical destination binding")

			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ticket, err := issuer.IssueForPeer(pair, "gateway", "client", time.Minute)
		if err != nil {
			t.Error(err)

			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		if err := json.NewEncoder(w).Encode(protocol.RelaySession{
			SessionID: pair, DeviceID: "gateway", DestinationDeviceID: "client", RelayURL: relayURL,
			RelayTransport: protocol.CapabilityUDPPair, Ticket: ticket, ExpiresInSeconds: 60,
		}); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	relayURL = "wss" + strings.TrimPrefix(server.URL, "https") + "/relay/udp"

	wg, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = wg.Close() })
	cfg := config.DefaultAgent()
	cfg.Relay.SignedPeers = true
	cfg.Relay.WebSocketURL = relayURL

	cfg.Relay.WireGuardAddress = wg.LocalAddr().String()
	cfg.Identity.ControlURL = server.URL
	cfg.Coordination.NetworkID = "home"
	leases := &leaseValue{
		value: protocol.CredentialLease{
			DeviceID:   "gateway",
			Credential: "current-lease",
			ExpiresAt:  time.Now().Add(time.Minute),
		},
	}
	endpoints := signedRuntimeEndpoint{bound: make(chan netip.AddrPort, 2)}

	owner, err := prepareSignedRelay(cfg, state, leases, root, endpoints, server.Client())
	if err != nil {
		t.Fatal(err)
	}

	if calls.Load() != 0 {
		t.Fatal("constructor contacted control")
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
			t.Error("prepared owner leaked")
		}
	})
	value := snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1, Devices: []snapshot.Device{
		{
			ID:                 "gateway",
			Role:               "gateway",
			IdentityPublicKey:  state.IdentityPublicKey,
			WireGuardPublicKey: state.WireGuard.PublicKey,
			OverlayAddress:     "10.243.0.2/32",
		},
		{
			ID:                 "client",
			Role:               "client",
			IdentityPublicKey:  client.IdentityPublicKey,
			WireGuardPublicKey: client.WireGuard.PublicKey,
			OverlayAddress:     "10.243.0.1/32",
		},
	}, Gateways: []snapshot.Gateway{{DeviceID: "gateway", Name: "Home"}}}

	envelope, err := snapshot.Sign(value, rootKey, "root")
	if err != nil {
		t.Fatal(err)
	}

	verified, err := snapshot.Verify(envelope, root, "home")
	if err != nil {
		t.Fatal(err)
	}

	if err := owner.Apply(ctx, verified); err != nil {
		t.Fatal(err)
	}

	select {
	case endpoint := <-endpoints.bound:
		if !endpoint.Addr().IsLoopback() {
			t.Fatal("not loopback")
		}
	case <-ctx.Done():
		t.Fatal("scoped relay never bound")
	}

	if calls.Load() != 1 {
		t.Fatal("initial admission duplicated or missing")
	}
}
