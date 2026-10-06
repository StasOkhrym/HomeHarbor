package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type leaseValue struct{ value protocol.CredentialLease }

func (s *leaseValue) Current(
	context.Context,
) (protocol.CredentialLease, error) {
	return s.value, nil
}

func TestRelayAdmissionReadsCurrentLease(t *testing.T) {
	headers := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).
			Encode(node.RelaySession{Ticket: "ticket", SessionID: "session", DestinationDeviceID: "destination", RelayURL: "wss://relay.test/relay/udp/v2", RelayTransport: protocol.CapabilityUDPPairV2})
	}))
	defer server.Close()
	cfg := config.DefaultClient()
	cfg.Identity.ControlURL = server.URL
	cfg.Relay.SessionID = "session"
	cfg.Relay.DestinationDevice = "destination"
	source := &leaseValue{
		value: protocol.CredentialLease{
			DeviceID:   "device",
			Credential: "first",
			ExpiresAt:  time.Now().Add(time.Minute),
		},
	}
	for _, credential := range []string{"first", "second"} {
		source.value.Credential = credential
		if _, err := issueRelaySession(context.Background(), cfg, "device", source); err != nil {
			t.Fatal(err)
		}
		if got := <-headers; got != "Bearer "+credential {
			t.Fatalf("admitted stale credential %q", got)
		}
	}
	source.value.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := issueRelaySession(context.Background(), cfg, "device", source); err == nil {
		t.Fatal("expired credential admitted")
	}
	select {
	case <-headers:
		t.Fatal("expired lease reached control")
	default:
	}
}

func TestRuntimeStartupRenewsPersistedLeaseUnderExistingStateOwner(t *testing.T) {
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")
	store, err := localstate.Open(cfg.Identity.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	state, err := node.LoadOrCreateFrom(store)
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID = "device"
	state.DeviceCredential = "persisted"
	state.CredentialExpiresAt = time.Now().Add(10 * time.Minute)
	if err := state.SaveTo(store); err != nil {
		t.Fatal(err)
	}
	lease := protocol.CredentialLease{
		DeviceID:   "device",
		Credential: "renewed",
		ExpiresAt:  time.Now().Add(15 * time.Minute),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices/credentials/rotate" ||
			r.Header.Get("Authorization") != "Bearer persisted" {
			t.Errorf("unexpected startup request %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(lease)
	}))
	defer server.Close()
	cfg.Identity.ControlURL = server.URL
	owner := prepareCredentials(cfg, state, store)
	current, err := owner.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := node.LoadOrCreateFrom(store)
	if err != nil {
		t.Fatal(err)
	}
	if current.Credential != "renewed" || persisted.DeviceCredential != current.Credential ||
		!persisted.CredentialExpiresAt.Equal(current.ExpiresAt) ||
		persisted.IdentityPrivateKey != state.IdentityPrivateKey {
		t.Fatal("startup did not durably renew the same identity")
	}
}
