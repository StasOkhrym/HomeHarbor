package coordination

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type liveAuthority struct {
	mu      sync.Mutex
	expiry  time.Time
	revoked bool
}

func (a *liveAuthority) Authenticate(_ context.Context, credential string) (devices.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if (a.revoked && credential == "source") || !a.expiry.After(time.Now()) {
		return devices.Device{}, errors.New("revoked or expired")
	}

	return devices.Device{
		ID:                  credential,
		Status:              devices.StatusActive,
		CredentialExpiresAt: a.expiry,
	}, nil
}

func (a *liveAuthority) Device(_ context.Context, id string) (devices.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := devices.StatusActive
	if a.revoked && id == "source" {
		status = devices.StatusRevoked
	}

	return devices.Device{ID: id, Status: status}, nil
}

func dialLeasePeer(t *testing.T, server *httptest.Server, id string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+id)
	c, _, err := websocket.Dial(
		ctx,
		"ws"+server.URL[4:],
		&websocket.DialOptions{HTTPHeader: header},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.CloseNow() })
	if err := wsjson.Write(
		ctx,
		c,
		protocol.Hello{
			Versions:     []uint16{protocol.CurrentVersion},
			Capabilities: []string{protocol.CapabilityRelay, protocol.CapabilityDirectUDP},
			DeviceID:     id,
		},
	); err != nil {
		t.Fatal(err)
	}
	var message any
	if err := wsjson.Read(ctx, c, &message); err != nil {
		t.Fatal(err)
	}
	if err := wsjson.Read(ctx, c, &message); err != nil {
		t.Fatal(err)
	}
	return c
}

func leaseHandler(a *liveAuthority) *Handler {
	return NewHandler(
		a,
		a,
		coordinationSnapshotStub{},
		nil,
		func(_ context.Context, s, d devices.Device) bool {
			return s.Status == devices.StatusActive && d.Status == devices.StatusActive
		},
	)
}

func TestLiveSourceRevokeDenied(t *testing.T) {
	a := &liveAuthority{expiry: time.Now().Add(time.Minute)}

	h := leaseHandler(a)
	s := httptest.NewServer(h)
	defer s.Close()

	source := dialLeasePeer(t, s, "source")

	dest := dialLeasePeer(t, s, "dest")

	a.mu.Lock()
	a.revoked = true

	a.mu.Unlock()
	payload, _ := json.Marshal(
		protocol.CandidateUpdate{
			DestinationDeviceID: "dest",
			Candidates: []protocol.Candidate{
				{Type: protocol.CandidateHost, Address: "203.0.113.5:1000", Priority: 1},
			},
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := wsjson.Write(
		ctx,
		source,
		protocol.Message{Type: "candidate.update", Payload: payload},
	); err != nil {
		t.Fatal(err)
	}

	var m protocol.Message

	if err := wsjson.Read(ctx, dest, &m); err == nil {
		t.Fatal("revoked live source forwarded candidates")
	}
}

func TestIdleSessionExpiryCloses(t *testing.T) {
	a := &liveAuthority{expiry: time.Now().Add(150 * time.Millisecond)}

	h := leaseHandler(a)
	s := httptest.NewServer(h)
	defer s.Close()

	c := dialLeasePeer(t, s, "source")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var m any

	err := wsjson.Read(ctx, c, &m)

	if err == nil || ctx.Err() != nil {
		t.Fatalf("idle session survived admission expiry: %v", err)
	}
}

func TestRotationReplacesSessionWithoutDuplicates(t *testing.T) {
	a := &liveAuthority{expiry: time.Now().Add(time.Minute)}

	h := leaseHandler(a)
	s := httptest.NewServer(h)
	defer s.Close()

	first := dialLeasePeer(t, s, "source")

	_ = dialLeasePeer(t, s, "source")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var m any

	if err := wsjson.Read(ctx, first, &m); err == nil || ctx.Err() != nil {
		t.Fatal("old session was not closed before replacement")
	}

	h.hub.mu.RLock()
	count := len(h.hub.peers)

	h.hub.mu.RUnlock()

	if count != 1 {
		t.Fatalf("live owners=%d", count)
	}
}

func TestIdleSessionRevalidatesAcrossReplicas(t *testing.T) {
	a := &liveAuthority{expiry: time.Now().Add(time.Minute)}
	h := leaseHandler(a)
	s := httptest.NewServer(h)
	defer s.Close()
	c := dialLeasePeer(t, s, "source")
	a.mu.Lock()
	a.revoked = true
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var m any
	if err := wsjson.Read(ctx, c, &m); err == nil || ctx.Err() != nil {
		t.Fatalf("idle revoked session survived authoritative recheck: %v", err)
	}
}

func TestLocalRevokeHintClosesSession(t *testing.T) {
	a := &liveAuthority{expiry: time.Now().Add(time.Minute)}

	h := leaseHandler(a)
	s := httptest.NewServer(h)
	defer s.Close()

	c := dialLeasePeer(t, s, "source")

	h.InvalidateDevice("source")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var m any

	if err := wsjson.Read(ctx, c, &m); err == nil || ctx.Err() != nil {
		t.Fatalf("local hint did not close session: %v", err)
	}
}

func TestMissingLeaseExpiryFailsClosed(t *testing.T) {
	h := NewHandler(noExpiryAuthority{}, nil, coordinationSnapshotStub{}, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer source")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing expiry status=%d", w.Code)
	}
}

type noExpiryAuthority struct{}

func (noExpiryAuthority) Authenticate(context.Context, string) (devices.Device, error) {
	return devices.Device{ID: "source", Status: devices.StatusActive}, nil
}
