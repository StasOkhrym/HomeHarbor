package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type changingLeases struct {
	mu    sync.Mutex
	lease protocol.CredentialLease
}

func (s *changingLeases) Current(context.Context) (protocol.CredentialLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lease, nil
}

func TestCoordinationReconnectReadsCurrentLease(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leases := &changingLeases{
		lease: protocol.CredentialLease{
			DeviceID:   "device",
			Credential: "first",
			ExpiresAt:  time.Now().Add(time.Minute),
		},
	}
	admissions := make(chan string, 3)
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
		if wsjson.Write(
			r.Context(),
			c,
			map[string]any{
				"type": "welcome",
				"protocol": protocol.Negotiated{
					Version:      protocol.CurrentVersion,
					Capabilities: []string{protocol.CapabilityRelay},
				},
			},
		) != nil {
			return
		}
		admissions <- r.Header.Get("Authorization")
		var m any
		_ = wsjson.Read(r.Context(), c, &m)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunCoordinationLoop(ctx, CoordinationConfig{URL: "ws" + server.URL[4:], Leases: leases, DeviceID: "device", NetworkID: "home", RootPublicKey: public, ReconnectInitial: time.Millisecond}, &snapshotRecorder{})
	}()
	defer func() { cancel(); <-done }()
	select {
	case first := <-admissions:
		if first != "Bearer first" {
			t.Fatalf("first admission=%s", first)
		}
	case <-time.After(time.Second):
		t.Fatal("no initial admission")
	}
	leases.mu.Lock()
	leases.lease.Credential = "second"
	leases.mu.Unlock()
	select {
	case second := <-admissions:
		if second != "Bearer second" {
			t.Fatalf("reconnect admission=%s", second)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lease replacement did not reconnect")
	}
}

func TestHistoryReadsCurrentLeasePerRequest(t *testing.T) {
	leases := &changingLeases{
		lease: protocol.CredentialLease{
			DeviceID:   "device",
			Credential: "first",
			ExpiresAt:  time.Now().Add(time.Minute),
		},
	}
	observed := make(chan string, 2)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.Header.Get("Authorization")
		_, _ = w.Write([]byte("[]"))
	}))
	defer s.Close()

	cfg := CoordinationConfig{URL: "ws" + s.URL[4:], DeviceID: "device", Leases: leases}
	for _, value := range []string{"first", "second"} {
		leases.mu.Lock()
		leases.lease.Credential = value

		leases.mu.Unlock()

		if _, err := fetchSnapshotHistory(context.Background(), cfg, 0, nil); err != nil {
			t.Fatal(err)
		}

		if got := <-observed; got != "Bearer "+value {
			t.Fatalf("history admitted %s", got)
		}
	}
}
