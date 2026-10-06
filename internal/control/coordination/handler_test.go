package coordination

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	controlprotocol "github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type coordinationAuthStub struct{}

func (coordinationAuthStub) Authenticate(context.Context, string) (devices.Device, error) {
	return devices.Device{
		ID:                  "device-1",
		Status:              devices.StatusActive,
		CredentialExpiresAt: time.Now().Add(time.Minute),
	}, nil
}

type coordinationSnapshotStub struct{ envelope snapshot.Envelope }

func (s coordinationSnapshotStub) Latest(context.Context) (snapshot.Envelope, error) {
	return s.envelope, nil
}

type peerCoordinationAuthStub struct {
	devices map[string]devices.Device
}

// Authentication alone must not implicitly supply candidate lookup privileges.
type authenticationOnly struct{ delegate Authenticator }

func (a authenticationOnly) Authenticate(
	ctx context.Context,
	credential string,
) (devices.Device, error) {
	return a.delegate.Authenticate(ctx, credential)
}

func (s peerCoordinationAuthStub) Authenticate(
	_ context.Context,
	credential string,
) (devices.Device, error) {
	for id, device := range s.devices {
		if credential == "credential-"+id {
			device.CredentialExpiresAt = time.Now().Add(time.Minute)
			return device, nil
		}
	}

	return devices.Device{}, fmt.Errorf("unknown credential")
}

func (s peerCoordinationAuthStub) Device(_ context.Context, id string) (devices.Device, error) {
	device, ok := s.devices[id]
	if !ok {
		return devices.Device{}, fmt.Errorf("unknown device")
	}

	return device, nil
}

func TestBroadcastSnapshotReachesConnectedPeer(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 2, PreviousHash: first.Hash},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(
		coordinationAuthStub{},
		nil,
		coordinationSnapshotStub{envelope: first},
		nil,
		nil,
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	requestHeader := make(http.Header)
	requestHeader.Set("Authorization", "Bearer credential")
	connection, _, err := websocket.Dial(
		context.Background(),
		"ws"+server.URL[len("http"):],
		&websocket.DialOptions{HTTPHeader: requestHeader},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.CloseNow() }()
	if err := wsjson.Write(
		context.Background(),
		connection,
		controlprotocol.Hello{
			Versions:     []uint16{controlprotocol.CurrentVersion},
			Capabilities: []string{controlprotocol.CapabilityRelay},
			DeviceID:     "device-1",
		},
	); err != nil {
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

func TestCandidateForwardingUsesAuthenticatedSourceIdentity(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	auth := peerCoordinationAuthStub{devices: map[string]devices.Device{
		"source":      {ID: "source", Status: devices.StatusActive},
		"destination": {ID: "destination", Status: devices.StatusActive},
	}}
	handler := NewHandler(
		authenticationOnly{auth},
		auth,
		coordinationSnapshotStub{envelope: first},
		nil,
		func(_ context.Context, source, destination devices.Device) bool {
			return source.ID != destination.ID
		},
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	dial := func(id string) *websocket.Conn {
		t.Helper()
		header := make(http.Header)
		header.Set("Authorization", "Bearer credential-"+id)
		connection, _, dialErr := websocket.Dial(
			context.Background(),
			"ws"+server.URL[len("http"):],
			&websocket.DialOptions{HTTPHeader: header},
		)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if writeErr := wsjson.Write(
			context.Background(),
			connection,
			controlprotocol.Hello{
				Versions: []uint16{controlprotocol.CurrentVersion},
				Capabilities: []string{
					controlprotocol.CapabilityRelay,
					controlprotocol.CapabilityDirectUDP,
				},
				DeviceID: id,
			},
		); writeErr != nil {
			t.Fatal(writeErr)
		}
		var welcome map[string]any
		if readErr := wsjson.Read(context.Background(), connection, &welcome); readErr != nil {
			t.Fatal(readErr)
		}
		var initial controlprotocol.Message
		if readErr := wsjson.Read(context.Background(), connection, &initial); readErr != nil {
			t.Fatal(readErr)
		}
		return connection
	}
	source := dial("source")
	defer func() { _ = source.CloseNow() }()
	destination := dial("destination")
	defer func() { _ = destination.CloseNow() }()

	payload, err := json.Marshal(controlprotocol.CandidateUpdate{
		SourceDeviceID:      "attacker-controlled-value",
		DestinationDeviceID: "destination",
		Candidates: []controlprotocol.Candidate{
			{Type: controlprotocol.CandidateHost, Address: "203.0.113.20:51820", Priority: 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Write(
		context.Background(),
		source,
		controlprotocol.Message{Type: "candidate.update", Payload: payload},
	); err != nil {
		t.Fatal(err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var forwarded controlprotocol.Message
	if err := wsjson.Read(readContext, destination, &forwarded); err != nil {
		t.Fatal(err)
	}
	var update controlprotocol.CandidateUpdate
	if err := json.Unmarshal(forwarded.Payload, &update); err != nil {
		t.Fatal(err)
	}
	if update.SourceDeviceID != "source" {
		t.Fatalf("source identity=%q, want authenticated source", update.SourceDeviceID)
	}
}

func TestCandidateForwardingRequiresAuthorizedPeer(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	auth := peerCoordinationAuthStub{devices: map[string]devices.Device{
		"source":      {ID: "source", Status: devices.StatusActive},
		"destination": {ID: "destination", Status: devices.StatusActive},
	}}
	handler := NewHandler(
		auth,
		auth,
		coordinationSnapshotStub{envelope: first},
		nil,
		func(context.Context, devices.Device, devices.Device) bool {
			return false
		},
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	dial := func(id string) *websocket.Conn {
		t.Helper()
		header := make(http.Header)
		header.Set("Authorization", "Bearer credential-"+id)
		connection, _, dialErr := websocket.Dial(
			context.Background(),
			"ws"+server.URL[len("http"):],
			&websocket.DialOptions{HTTPHeader: header},
		)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if writeErr := wsjson.Write(
			context.Background(),
			connection,
			controlprotocol.Hello{
				Versions: []uint16{controlprotocol.CurrentVersion},
				Capabilities: []string{
					controlprotocol.CapabilityRelay,
					controlprotocol.CapabilityDirectUDP,
				},
				DeviceID: id,
			},
		); writeErr != nil {
			t.Fatal(writeErr)
		}
		var welcome map[string]any
		if readErr := wsjson.Read(context.Background(), connection, &welcome); readErr != nil {
			t.Fatal(readErr)
		}
		var initial controlprotocol.Message
		if readErr := wsjson.Read(context.Background(), connection, &initial); readErr != nil {
			t.Fatal(readErr)
		}
		return connection
	}
	source := dial("source")
	defer func() { _ = source.CloseNow() }()
	destination := dial("destination")
	defer func() { _ = destination.CloseNow() }()

	payload, err := json.Marshal(controlprotocol.CandidateUpdate{
		DestinationDeviceID: "destination",
		Candidates: []controlprotocol.Candidate{
			{Type: controlprotocol.CandidateHost, Address: "203.0.113.20:51820", Priority: 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Write(
		context.Background(),
		source,
		controlprotocol.Message{Type: "candidate.update", Payload: payload},
	); err != nil {
		t.Fatal(err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var forwarded controlprotocol.Message
	if err := wsjson.Read(readContext, destination, &forwarded); err == nil {
		t.Fatal("unauthorized candidate update was forwarded")
	}
}

func TestCandidateForwardingRequiresDirectCapability(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(
		snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1},
		privateKey,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	auth := peerCoordinationAuthStub{devices: map[string]devices.Device{
		"source":      {ID: "source", Status: devices.StatusActive},
		"destination": {ID: "destination", Status: devices.StatusActive},
	}}
	handler := NewHandler(
		auth,
		auth,
		coordinationSnapshotStub{envelope: first},
		nil,
		func(context.Context, devices.Device, devices.Device) bool {
			return true
		},
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	dial := func(id string, capabilities []string) *websocket.Conn {
		t.Helper()
		header := make(http.Header)
		header.Set("Authorization", "Bearer credential-"+id)
		connection, _, dialErr := websocket.Dial(
			context.Background(),
			"ws"+server.URL[len("http"):],
			&websocket.DialOptions{HTTPHeader: header},
		)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		if writeErr := wsjson.Write(
			context.Background(),
			connection,
			controlprotocol.Hello{
				Versions:     []uint16{controlprotocol.CurrentVersion},
				Capabilities: capabilities,
				DeviceID:     id,
			},
		); writeErr != nil {
			t.Fatal(writeErr)
		}
		var welcome map[string]any
		if readErr := wsjson.Read(context.Background(), connection, &welcome); readErr != nil {
			t.Fatal(readErr)
		}
		var initial controlprotocol.Message
		if readErr := wsjson.Read(context.Background(), connection, &initial); readErr != nil {
			t.Fatal(readErr)
		}
		return connection
	}
	source := dial("source", []string{controlprotocol.CapabilityRelay})
	defer func() { _ = source.CloseNow() }()
	destination := dial(
		"destination",
		[]string{controlprotocol.CapabilityRelay, controlprotocol.CapabilityDirectUDP},
	)
	defer func() { _ = destination.CloseNow() }()

	payload, err := json.Marshal(controlprotocol.CandidateUpdate{
		DestinationDeviceID: "destination",
		Candidates: []controlprotocol.Candidate{
			{Type: controlprotocol.CandidateHost, Address: "203.0.113.20:51820", Priority: 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Write(
		context.Background(),
		source,
		controlprotocol.Message{Type: "candidate.update", Payload: payload},
	); err != nil {
		t.Fatal(err)
	}
	readContext, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	var forwarded controlprotocol.Message
	if err := wsjson.Read(readContext, destination, &forwarded); err == nil {
		t.Fatal("candidate update from a relay-only peer was forwarded")
	}
}
