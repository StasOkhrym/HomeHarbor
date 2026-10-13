package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/client/macos"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
	"github.com/StasOkhrym/homeharbor/internal/platform/trust"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type nativeRuntimeHelper struct {
	requests []macos.HelperRequest
	stop     context.CancelFunc
}

func (h *nativeRuntimeHelper) Execute(ctx context.Context, request macos.HelperRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	var copy macos.HelperRequest

	if err := json.Unmarshal(data, &copy); err != nil {
		return err
	}

	h.requests = append(h.requests, copy)
	if request.Action == "apply" {
		h.stop()
	}

	return nil
}

func TestNativeCoordinationUsesSignedControllerAndCleansAfterWorkers(t *testing.T) {
	cfg := nativeRuntimeFixture(t)
	root, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	state, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID = "client-1"
	gateway, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{
		NetworkID: cfg.Coordination.NetworkID,
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 state.DeviceID,
				Role:               "client",
				WireGuardPublicKey: state.WireGuard.PublicKey,
				OverlayAddress:     "10.243.0.3/32",
			},
			{
				ID:                 "gateway-1",
				Role:               "gateway",
				WireGuardPublicKey: gateway.WireGuard.PublicKey,
				OverlayAddress:     "10.243.0.2/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway-1"}},
		Routes: []snapshot.Route{
			{
				ID:           "private",
				GatewayID:    "gateway-1",
				Prefix:       "10.241.50.0/24",
				DomainSuffix: "sandbox.home.arpa",
				Resolver:     "10.241.50.53",
			},
		},
	}, signing, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer credential" {
			t.Error("native coordination omitted the current credential")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/v1/coordination/snapshots" {
			_ = json.NewEncoder(w).Encode([]snapshot.Envelope{envelope})
			return
		}
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = connection.CloseNow() }()
		var hello protocol.Hello
		if err := wsjson.Read(r.Context(), connection, &hello); err != nil {
			t.Error(err)
			return
		}
		if err := wsjson.Write(r.Context(), connection, map[string]any{
			"type": "welcome",
			"protocol": protocol.Negotiated{
				Version:      protocol.CurrentVersion,
				Capabilities: []string{protocol.CapabilityUDPPair},
			},
		}); err != nil {
			t.Error(err)
			return
		}
		payload, _ := json.Marshal(envelope)
		_ = wsjson.Write(
			r.Context(),
			connection,
			protocol.Message{Type: "network.snapshot", Payload: payload},
		)
		var ignored protocol.Message
		_ = wsjson.Read(r.Context(), connection, &ignored)
	}))
	defer server.Close()
	if err := os.WriteFile(
		cfg.Identity.CAFile,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	client, err := trust.NewHTTPClientFromCAFile(cfg.Identity.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	cfg.Coordination.URL = strings.Replace(server.URL, "https://", "wss://", 1) + "/coordination"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	helper := &nativeRuntimeHelper{stop: cancel}
	owner, err := prepareNativeController(cfg, state, root, helper)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal(err)
	}
	leases := &leaseValue{
		value: protocol.CredentialLease{
			DeviceID:   state.DeviceID,
			Credential: "credential",
			ExpiresAt:  time.Now().Add(time.Minute),
		},
	}
	worker, err := prepareCoordination(
		Client,
		cfg,
		state,
		leases,
		root,
		owner,
		nil,
		candidateBindings{},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{
		workers: []lifecycle.Worker{{Name: "coordination", Component: worker}},
		close:   func() error { return owner.Close(context.Background()) },
	}
	if err := app.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(helper.requests) != 3 || helper.requests[0].Action != "close" ||
		helper.requests[1].Action != "apply" ||
		helper.requests[2].Action != "close" {
		t.Fatalf(
			"native startup/apply/shutdown ownership was not wired: %d requests",
			len(helper.requests),
		)
	}
	request := helper.requests[1]
	if request.PrivateKey != state.WireGuard.PrivateKey || request.Plan.Revision != 1 ||
		request.Plan.Routes[0].String() != "10.241.50.0/24" {
		t.Fatal("native runtime did not submit the signed identity and private route")
	}
	data, err := os.ReadFile(cfg.Identity.StatePath + ".snapshot")
	if err != nil {
		t.Fatal("native runtime failed to checkpoint the applied signed envelope")
	}
	var checkpoint snapshot.Envelope
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Verify(checkpoint, root, cfg.Coordination.NetworkID); err != nil {
		t.Fatal(err)
	}
}
