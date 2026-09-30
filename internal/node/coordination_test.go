package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

type cursorRecorder struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	revision []uint64
}

func (r *cursorRecorder) Apply(_ context.Context, value snapshot.NetworkSnapshot) error {
	r.mu.Lock()
	r.revision = append(r.revision, value.Revision)
	count := len(r.revision)

	r.mu.Unlock()
	if count == 2 {
		r.cancel()
	}

	return nil
}

func (r *cursorRecorder) revisions() []uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]uint64(nil), r.revision...)
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

func TestRunCoordinationLoopRetainsCursorAcrossReconnect(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 2, PreviousHash: first.Hash}, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	var connections atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCoordinationTestHistory(w, r, []snapshot.Envelope{first, second}) {
			return
		}
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
		if writeErr := wsjson.Write(r.Context(), connection, map[string]any{"type": "welcome", "protocol": controlprotocol.Negotiated{Version: controlprotocol.CurrentVersion, Capabilities: []string{controlprotocol.CapabilityRelay}}}); writeErr != nil {
			t.Errorf("welcome: %v", writeErr)
			return
		}
		envelope := first
		if connections.Add(1) > 1 {
			envelope = second
		}
		payload, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			t.Errorf("marshal envelope: %v", marshalErr)
			return
		}
		if writeErr := wsjson.Write(r.Context(), connection, controlprotocol.Message{Type: "network.snapshot", Payload: payload}); writeErr != nil {
			t.Errorf("snapshot: %v", writeErr)
			return
		}
		if connections.Load() == 1 {
			_ = connection.Close(websocket.StatusServiceRestart, "test reconnect")
			return
		}
		consumeCoordinationTestPeer(r.Context(), connection)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	recorder := &cursorRecorder{cancel: cancel}
	err = RunCoordinationLoop(ctx, CoordinationConfig{
		URL:              "ws" + server.URL[len("http"):],
		Credential:       "credential",
		DeviceID:         "device-1",
		NetworkID:        "home",
		RootPublicKey:    publicKey,
		ReconnectInitial: 10 * time.Millisecond,
		ReconnectMax:     20 * time.Millisecond,
	}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if got := recorder.revisions(); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("applied revisions=%v, want [1 2]", got)
	}
}

func TestRunCoordinationPublishesCandidateUpdatesAfterWelcome(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

func TestCandidatePublisherStopsWhenSessionContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	heartbeat := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		runCandidatePublisher(ctx, heartbeat, nil, func(any) error {
			return nil
		}, func() error {
			return nil
		})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("candidate publisher did not stop with its session context")
	}
}

func newCoordinationTestServer(t *testing.T, envelope snapshot.Envelope) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveCoordinationTestHistory(w, r, []snapshot.Envelope{envelope}) {
			return
		}
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
		consumeCoordinationTestPeer(r.Context(), connection)
	}))
}
