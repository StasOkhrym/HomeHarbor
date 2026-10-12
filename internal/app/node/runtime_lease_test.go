package node

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/trust"
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
			Encode(node.RelaySession{Ticket: "ticket", SessionID: "session", DestinationDeviceID: "destination", RelayURL: "wss://relay.test/relay/udp", RelayTransport: protocol.CapabilityUDPPair})
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

		if _, err := issueRelaySession(
			context.Background(),
			cfg,
			"device",
			source,
			nil,
		); err != nil {
			t.Fatal(err)
		}

		if got := <-headers; got != "Bearer "+credential {
			t.Fatalf("admitted stale credential %q", got)
		}
	}

	source.value.ExpiresAt = time.Now().Add(-time.Second)

	if _, err := issueRelaySession(context.Background(), cfg, "device", source, nil); err == nil {
		t.Fatal("expired credential admitted")
	}

	select {
	case <-headers:
		t.Fatal("expired lease reached control")
	default:
	}
}

func TestRelayAdmissionKeepsConfiguredAudienceEndpoint(t *testing.T) {
	requests := make(chan struct{}, 1)
	relay := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case requests <- struct{}{}:
		default:
		}

		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer relay.Close()

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(node.RelaySession{
			Ticket:              "ticket",
			SessionID:           "session",
			DestinationDeviceID: "destination",
			RelayURL:            "wss://host-only.invalid/relay/udp",
			RelayTransport:      protocol.CapabilityUDPPair,
		})
	}))
	defer control.Close()

	cfg := config.DefaultClient()
	cfg.Identity.ControlURL = control.URL
	cfg.Relay.WebSocketURL = strings.Replace(relay.URL, "https://", "wss://", 1) + "/relay/udp"
	cfg.Relay.SessionID = "session"
	cfg.Relay.DestinationDevice = "destination"
	source := &leaseValue{value: protocol.CredentialLease{
		DeviceID: "device", Credential: "credential", ExpiresAt: time.Now().Add(time.Minute),
	}}

	component, err := prepareRelay(
		context.Background(),
		cfg,
		node.State{DeviceID: "device"},
		source,
		nil,
		nil,
		nil,
		relay.Client(),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	finished := make(chan error, 1)
	go func() { finished <- component.Run(ctx) }()
	select {
	case <-requests:
	case err := <-finished:
		t.Fatalf("relay bridge exited without dialing its configured audience endpoint: %v", err)
	case <-ctx.Done():
		t.Fatal("relay bridge did not dial its configured audience endpoint")
	}

	cancel()
	<-finished
}

func TestRelayAdmissionUsesExplicitControlCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(node.RelaySession{
			Ticket: "ticket", SessionID: "session", DestinationDeviceID: "destination",
			RelayURL: "wss://relay.test/relay/udp", RelayTransport: protocol.CapabilityUDPPair,
		})
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "control-ca.pem")

	certificate := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw},
	)

	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultClient()
	cfg.Identity.ControlURL = server.URL
	cfg.Identity.CAFile = caFile
	cfg.Relay.SessionID = "session"
	cfg.Relay.DestinationDevice = "destination"
	source := &leaseValue{value: protocol.CredentialLease{
		DeviceID: "device", Credential: "credential", ExpiresAt: time.Now().Add(time.Minute),
	}}

	client, err := trust.NewHTTPClientFromCAFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()

	if _, err := issueRelaySession(
		context.Background(),
		cfg,
		"device",
		source,
		client,
	); err != nil {
		t.Fatalf("explicit control CA did not reach relay admission: %v", err)
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

	owner := prepareCredentials(cfg, state, store, nil)

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

func TestRuntimeRenewsClaimedCredentialWithExplicitCA(t *testing.T) {
	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(t.TempDir(), "state.json")
	state, err := node.LoadOrCreate(cfg.Identity.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	state.DeviceID = "client-1"
	state.DeviceCredential = "persisted"
	state.CredentialExpiresAt = time.Now().Add(10 * time.Minute)
	if err := state.Save(cfg.Identity.StatePath); err != nil {
		t.Fatal(err)
	}
	rotated := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/devices/credentials/rotate" ||
			r.Header.Get("Authorization") != "Bearer persisted" {
			t.Errorf("unexpected runtime control request %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.CredentialLease{
			DeviceID:   "client-1",
			Credential: "renewed",
			ExpiresAt:  time.Now().Add(15 * time.Minute),
		})
		rotated <- struct{}{}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw},
	)
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Identity.ControlURL = server.URL
	cfg.Identity.CAFile = caFile
	app, err := NewRuntime(context.Background(), Client, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	select {
	case <-rotated:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("runtime did not use its explicit control CA")
	}
	deadline := time.After(5 * time.Second)
	for {
		saved, err := os.ReadFile(cfg.Identity.StatePath)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if strings.Contains(string(saved), `"device_credential": "renewed"`) {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("runtime received but did not persist renewed credential")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	reloaded, err := node.Load(cfg.Identity.StatePath)
	if err != nil || reloaded.DeviceCredential != "renewed" {
		t.Fatalf("renewed credential was not saved: renewed=%t err=%v",
			reloaded.DeviceCredential == "renewed", err)
	}
}
