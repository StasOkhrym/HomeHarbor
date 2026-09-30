package coordination

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlprotocol "github.com/sokhrym/go-tunnels/internal/protocol"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type coordinationAuthStub struct{}

func (coordinationAuthStub) Authenticate(context.Context, string) (devices.Device, error) {
	return devices.Device{ID: "device-1", Status: devices.StatusActive}, nil
}

type coordinationSnapshotStub struct{ envelope snapshot.Envelope }

func (s coordinationSnapshotStub) Latest(context.Context) (snapshot.Envelope, error) {
	return s.envelope, nil
}

func TestBroadcastSnapshotReachesConnectedPeer(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
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
	handler := NewHandler(coordinationAuthStub{}, coordinationSnapshotStub{envelope: first}, nil, nil)
	server := httptest.NewServer(handler)
	defer server.Close()

	requestHeader := make(http.Header)
	requestHeader.Set("Authorization", "Bearer credential")
	connection, _, err := websocket.Dial(context.Background(), "ws"+server.URL[len("http"):], &websocket.DialOptions{HTTPHeader: requestHeader})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseNow() }()
	if err := wsjson.Write(context.Background(), connection, controlprotocol.Hello{Versions: []uint16{controlprotocol.CurrentVersion}, Capabilities: []string{controlprotocol.CapabilityRelay}, DeviceID: "device-1"}); err != nil {
		t.Fatal(err)
	}
	var welcome map[string]any
	if err := wsjson.Read(context.Background(), connection, &welcome); err != nil {
		t.Fatal(err)
	}
	var initial controlprotocol.Message
	if err := wsjson.Read(context.Background(), connection, &initial); err != nil {
		t.Fatal(err)
	}
	if initial.Type != "network.snapshot" {
		t.Fatalf("initial message type = %q", initial.Type)
	}

	handler.BroadcastSnapshot(context.Background(), second)
	var update controlprotocol.Message
	if err := wsjson.Read(context.Background(), connection, &update); err != nil {
		t.Fatal(err)
	}
	if update.Type != "network.snapshot" {
		t.Fatalf("broadcast message type = %q", update.Type)
	}
}
