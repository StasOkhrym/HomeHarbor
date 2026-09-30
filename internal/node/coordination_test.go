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
