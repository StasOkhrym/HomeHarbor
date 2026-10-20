package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/StasOkhrym/homeharbor/internal/control/coordination"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	controltelemetry "github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/relay"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

// Disposable loopback-only fixture: no kernel WireGuard, OS trust or routes.
func main() {
	if len(os.Args) != 2 {
		panic("fixture config output path required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	ctx, deadline := context.WithTimeout(ctx, 3*time.Minute)
	defer deadline()

	issuer := relay.TicketIssuer{Key: []byte("01234567890123456789012345678901")}
	pair, err := relay.NewUDPPair(issuer, relay.UDPPairConfig{ListenIP: net.ParseIP("127.0.0.1")})
	check(err)
	defer func() { check(pair.Close()) }()

	mux := http.NewServeMux()
	mux.Handle("/relay/udp", pair)
	server := httptest.NewTLSServer(mux)
	server.Config.ErrorLog = log.New(os.Stderr, "fixture TLS: ", 0)
	defer server.Close()

	wss := func(s *httptest.Server) string { return "wss" + strings.TrimPrefix(s.URL, "https") + "/relay/udp" }
	var redirected atomic.Int32
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer sink.Close()

	redirect := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, sink.URL+"/relay/udp", http.StatusFound)
		}),
	)
	defer redirect.Close()

	var held atomic.Int32
	hold := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()

		held.Add(1)
		_, _, _ = c.Read(r.Context())
	}))
	defer hold.Close()

	oversize := httptest.NewTLSServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = c.CloseNow() }()

			_ = c.Write(r.Context(), websocket.MessageText, []byte(strings.Repeat("x", 2049)))
			_, _, _ = c.Read(r.Context())
		}),
	)
	defer oversize.Close()

	telemetryStore := &fixtureTelemetryStore{}
	stats := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		telemetryStore.mu.Lock()
		defer telemetryStore.mu.Unlock()

		_ = json.NewEncoder(w).
			Encode(map[string]any{"redirected": redirected.Load(), "held": held.Load(), "telemetry_reports": telemetryStore.count, "telemetry_sequence": telemetryStore.sequence})
	}))
	defer stats.Close()

	root := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	credential := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	expiry := time.Now().Add(120 * time.Second)

	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		ed25519.NewKeyFromSeed(make([]byte, 32)),
		"root-1",
	)
	check(err)

	second, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 2, PreviousHash: first.Hash},
		ed25519.NewKeyFromSeed(make([]byte, 32)),
		"root-1",
	)
	check(err)
	coord := coordination.NewHandlerWithHistory(
		fixtureAuthority{credential, expiry},
		nil,
		fixtureHistory{[]snapshot.Envelope{first, second}},
		nil,
		nil,
	)
	coord.Telemetry = controltelemetry.NewService(telemetryStore, nil, time.Now)
	coordDone := make(chan error, 1)
	go func() { coordDone <- coord.Run(ctx) }()
	defer func() { cancel(); check(<-coordDone) }()

	mux.Handle("/api/v1/coordination", coord)
	mux.HandleFunc("/api/v1/coordination/snapshots", coord.ServeHistory)

	session, err := protocol.RelayPairSessionID("home", root, "client-1", "gateway-1")
	check(err)
	ticket := func(device, peer string) string {
		t, err := issuer.IssueForPeer(session, device, peer, 120*time.Second)
		check(err)
		return t
	}

	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	check(err)
	defer func() { _ = wg.Close() }() // Also close on early failure; normal shutdown joins below.

	bridge, err := relay.NewUDPPairBridge(relay.UDPPairBridgeConfig{
		ControlURL: wss(server), HTTPClient: server.Client(),
		SessionID: session, DeviceID: "gateway-1", DestinationDeviceID: "client-1",
		Ticket:           ticket("gateway-1", "client-1"),
		ListenAddress:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		WireGuardAddress: wg.LocalAddr().(*net.UDPAddr), RejectUnconfirmedSources: true,
	})
	check(err)
	defer func() { check(bridge.Close()) }()

	check(bridge.Bind(ctx, ticket("gateway-1", "client-1")))
	// Echo at the WireGuard boundary; this deliberately proves no WG encryption.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)

		buffer := make([]byte, 65535)
		for {
			n, source, err := wg.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			if _, err = wg.WriteToUDP(buffer[:n], source); err != nil {
				return
			}
		}
	}()
	reply := func(url string) map[string]any {
		return map[string]any{
			"session_id":            session,
			"device_id":             "client-1",
			"destination_device_id": "gateway-1",
			"relay_transport":       "udp_pair",
			"relay_url":             url,
			"ticket":                ticket("client-1", "gateway-1"),
			"expires_in_seconds":    120,
		}
	}
	config := map[string]any{
		"root":               root,
		"certificate":        server.Certificate().Raw,
		"tickets":            []any{reply(wss(server)), reply(wss(server))},
		"redirect_ticket":    reply(wss(redirect)),
		"sink_url":           sink.URL,
		"stats_url":          stats.URL,
		"hold_ticket":        reply(wss(hold)),
		"oversize_ticket":    reply(wss(oversize)),
		"control_endpoint":   server.URL,
		"control_credential": credential,
		"control_expiry":     expiry.Unix(),
	}
	data, err := json.Marshal(config)
	check(err)
	// Publish readiness only after the complete private fixture config is closed.
	temporary := os.Args[1] + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	check(err)

	_, err = file.Write(data)
	check(err)
	check(file.Close())
	check(os.Rename(temporary, os.Args[1]))
	fmt.Println("Loopback Go TLS/UDP fixture ready")
	<-ctx.Done()
	check(wg.Close())
	<-echoDone
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

// Only the external account authority/store is a disposable fixture. The
// coordination negotiation, frames, heartbeat and history HTTP handler are real.
type fixtureAuthority struct {
	credential string
	expiry     time.Time
}

func (a fixtureAuthority) Authenticate(
	_ context.Context,
	credential string,
) (devices.Device, error) {
	if credential != a.credential || time.Now().After(a.expiry) {
		return devices.Device{}, fmt.Errorf("fixture credential rejected")
	}

	return devices.Device{
		ID:                  "client-1",
		Role:                devices.RoleClient,
		Status:              devices.StatusActive,
		CredentialExpiresAt: a.expiry,
	}, nil
}

type fixtureHistory struct{ entries []snapshot.Envelope }

func (s fixtureHistory) Latest(context.Context) (snapshot.Envelope, error) {
	return s.entries[len(s.entries)-1], nil
}

func (s fixtureHistory) History(
	_ context.Context,
	after uint64,
	limit int,
) ([]snapshot.Envelope, error) {
	if after >= uint64(len(s.entries)) {
		return []snapshot.Envelope{}, nil
	}

	end := min(int(after)+limit, len(s.entries))

	return s.entries[after:end], nil
}

type fixtureTelemetryStore struct {
	mu                   sync.Mutex
	generation, sequence uint64
	count                int
}

func (s *fixtureTelemetryStore) Begin(_ context.Context, _ string, _ time.Time) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.generation++
	s.sequence = 0

	return s.generation, nil
}

func (s *fixtureTelemetryStore) Record(
	_ context.Context,
	id string,
	role devices.Role,
	report protocol.TelemetryReport,
	_ time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id != "client-1" || role != devices.RoleClient || report.Generation != s.generation ||
		report.Sequence <= s.sequence {
		return controltelemetry.ErrStaleReport
	}

	s.sequence = report.Sequence
	s.count++
	return nil
}
