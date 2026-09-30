package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type snapshotRecorder struct {
	cancel context.CancelFunc
	value  snapshot.NetworkSnapshot
	called bool
}

func (r *snapshotRecorder) Apply(_ context.Context, value snapshot.NetworkSnapshot) error {
	r.value = value
	r.called = true

	r.cancel()
	return nil
}

func TestRunCoordinationVerifiesAndAppliesSignedSnapshot(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	server := newCoordinationTestServer(t, envelope)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	recorder := &snapshotRecorder{cancel: cancel}
	err = RunCoordination(ctx, CoordinationConfig{URL: "ws" + server.URL[len("http"):], Credential: "credential", DeviceID: "device-1", NetworkID: "home", RootPublicKey: publicKey, HeartbeatEvery: time.Hour}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if !recorder.called || recorder.value.Revision != 1 {
		t.Fatalf("recorder=%#v", recorder)
	}
}

func TestRunCoordinationLoopStopsOnCancellationDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	err := RunCoordinationLoop(ctx, CoordinationConfig{
		URL:              "ws://127.0.0.1:1",
		Credential:       "credential",
		DeviceID:         "device-1",
		NetworkID:        "home",
		RootPublicKey:    make([]byte, ed25519.PublicKeySize),
		ReconnectInitial: time.Second,
		ReconnectMax:     time.Second,
	}, &snapshotRecorder{})
	if err != nil {
		t.Fatalf("RunCoordinationLoop() error = %v", err)
	}
}

func TestRunCoordinationPublishesCandidateUpdatesAfterWelcome(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var received controlprotocol.CandidateUpdate
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, acceptErr := websocket.Accept(w, r, nil)
		if acceptErr != nil {
			t.Errorf("accept: %v", acceptErr)
			return
		}
		defer func() { _ = connection.CloseNow() }()
		var hello controlprotocol.Hello
		if readErr := wsjson.Read(r.Context(), connection, &hello); readErr != nil {
			t.Errorf("hello: %v", readErr)
			return
		}
		if writeErr := wsjson.Write(r.Context(), connection, map[string]any{"type": "welcome", "protocol": controlprotocol.Negotiated{Version: controlprotocol.CurrentVersion, Capabilities: []string{controlprotocol.CapabilityRelay, controlprotocol.CapabilityDirectUDP}}}); writeErr != nil {
			t.Errorf("welcome: %v", writeErr)
			return
		}
		var message controlprotocol.Message
		if readErr := wsjson.Read(r.Context(), connection, &message); readErr != nil {
			t.Errorf("candidate message: %v", readErr)
			return
		}
		if message.Type != "candidate.update" {
			t.Errorf("message type=%q, want candidate.update", message.Type)
			return
		}
		if unmarshalErr := json.Unmarshal(message.Payload, &received); unmarshalErr != nil {
			t.Errorf("candidate payload: %v", unmarshalErr)
			return
		}
		cancel()
	}))
	defer server.Close()
	err = RunCoordination(ctx, CoordinationConfig{
		URL:           "ws" + server.URL[len("http"):],
		Credential:    "credential",
		DeviceID:      "client",
		NetworkID:     "home",
		RootPublicKey: publicKey,
		CandidateProvider: func(context.Context) ([]controlprotocol.CandidateUpdate, error) {
			return []controlprotocol.CandidateUpdate{{DestinationDeviceID: "gateway", Candidates: []controlprotocol.Candidate{{Type: controlprotocol.CandidateHost, Address: "192.168.1.20:51820", Priority: 100}}}}, nil
		},
	}, &snapshotRecorder{cancel: cancel})
	if err != nil {
		t.Fatal(err)
	}
	if received.DestinationDeviceID != "gateway" || len(received.Candidates) != 1 {
		t.Fatalf("received candidate update=%#v", received)
	}
}

func newCoordinationTestServer(t *testing.T, envelope snapshot.Envelope) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer func() { _ = connection.CloseNow() }()
		var hello controlprotocol.Hello
		if err := wsjson.Read(r.Context(), connection, &hello); err != nil {
			t.Errorf("hello: %v", err)
			return
		}
		if err := wsjson.Write(r.Context(), connection, map[string]any{"type": "welcome", "protocol": controlprotocol.Negotiated{Version: controlprotocol.CurrentVersion, Capabilities: []string{controlprotocol.CapabilityRelay}}}); err != nil {
			t.Errorf("welcome: %v", err)
			return
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			t.Errorf("marshal envelope: %v", err)
			return
		}
		_ = wsjson.Write(r.Context(), connection, controlprotocol.Message{Type: "network.snapshot", Payload: payload})
		<-r.Context().Done()
	}))
}
