package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type blockedTelemetrySource struct{ entered chan struct{} }

func (s blockedTelemetrySource) Snapshot(ctx context.Context) (protocol.TelemetryReport, error) {
	close(s.entered)
	<-ctx.Done()
	return protocol.TelemetryReport{}, ctx.Err()
}
func (blockedTelemetrySource) Changes() <-chan struct{}     { return nil }
func (blockedTelemetrySource) PathChanges() <-chan struct{} { return nil }

func TestTelemetryPublisherCancelsAndJoinsCollection(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	source := blockedTelemetrySource{entered: make(chan struct{})}
	joined := make(chan struct{})
	var writes atomic.Int32
	go func() {
		defer close(joined)

		runTelemetryPublisher(
			ctx,
			41,
			source,
			make(chan time.Time),
			func(any) error { writes.Add(1); return nil },
		)
	}()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("collection never started")
	}

	cancel()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("publisher did not join cancelled collection")
	}

	if writes.Load() != 0 {
		t.Fatal("publisher wrote after cancellation")
	}
}

type telemetryNoopApplier struct{}

func (telemetryNoopApplier) Apply(context.Context, snapshot.NetworkSnapshot) error { return nil }

func TestCoordinationTelemetryReconnectUsesNewGenerationAndSameRuntime(t *testing.T) {
	value, _, _ := telemetryTopology(t)
	value.Revision = 1

	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	envelope, err := snapshot.Sign(value, private, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	source, err := NewRuntimeTelemetry(TelemetryConfig{DeviceID: "gateway", Role: "gateway"})
	if err != nil {
		t.Fatal(err)
	}

	source.Applied(value)
	reports := make(chan protocol.TelemetryReport, 2)
	var admissions atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()

		var hello protocol.Hello
		if wsjson.Read(r.Context(), c, &hello) != nil {
			return
		}

		generation := 40 + admissions.Add(1)
		if !containsCapability(hello.Capabilities, protocol.CapabilityTelemetry) {
			t.Error("telemetry not advertised")

			return
		}
		if wsjson.Write(
			r.Context(),
			c,
			protocol.Welcome{
				Type: "welcome",
				Protocol: protocol.Negotiated{
					Version: protocol.CurrentVersion,
					Capabilities: []string{
						protocol.CapabilityUDPPair,
						protocol.CapabilityTelemetry,
					},
				},
				TelemetryGeneration: generation,
			},
		) != nil {
			return
		}

		payload, _ := json.Marshal(envelope)
		if wsjson.Write(
			r.Context(),
			c,
			protocol.Message{Type: "network.snapshot", Payload: payload},
		) != nil {
			return
		}

		var message protocol.Message
		if wsjson.Read(r.Context(), c, &message) != nil {
			return
		}

		var report protocol.TelemetryReport
		if message.Type != "telemetry.report" || json.Unmarshal(message.Payload, &report) != nil {
			t.Error("missing runtime report")

			return
		}

		reports <- report
		if generation == 41 {
			_ = c.Close(websocket.StatusGoingAway, "restart")
			return
		}

		_ = wsjson.Read(r.Context(), c, &message)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- RunCoordinationLoop(ctx, CoordinationConfig{URL: "ws" + strings.TrimPrefix(server.URL, "http"), Credential: "device-credential", DeviceID: "gateway", NetworkID: "home", RootPublicKey: root, ReconnectInitial: time.Millisecond, ReconnectMax: 5 * time.Millisecond, Telemetry: source}, telemetryNoopApplier{})
	}()
	var got []protocol.TelemetryReport
	for len(got) < 2 {
		select {
		case report := <-reports:
			got = append(got, report)
		case <-ctx.Done():
			t.Fatal("runtime reports did not survive reconnect")
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("coordination/telemetry did not join")
	}

	if got[0].Generation != 41 || got[1].Generation != 42 || got[0].Sequence != 1 ||
		got[1].Sequence != 1 ||
		got[0].RuntimeID != got[1].RuntimeID ||
		got[0].State != protocol.RuntimeRunning {
		t.Fatalf("control reconnect became VPN restart or reused generation: %+v", got)
	}
}

func containsCapability(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
