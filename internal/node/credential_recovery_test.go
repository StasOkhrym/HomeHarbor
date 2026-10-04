package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestRecoverCredentialPreservesIdentityAndPersistsLeaseWithOwner(t *testing.T) {
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}

	state.DeviceID = "device"
	state.DeviceCredential = "expired"
	original := state

	expiry := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/devices/credentials/challenge":
			var request struct {
				DeviceID string `json:"device_id"`
			}

			if err := json.NewDecoder(r.Body).
				Decode(&request); err != nil ||
				request.DeviceID != state.DeviceID {
				t.Error("wrong recovery identity")
			}

			_ = json.NewEncoder(w).
				Encode(protocol.CredentialChallenge{Version: 1, NetworkID: "network", DeviceID: "device", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: time.Now().Add(time.Minute).Unix()})
		case "/api/v1/devices/credentials/recovery":
			var proof protocol.CredentialProof

			if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
				t.Error(err)
			}

			public, _ := base64.RawURLEncoding.DecodeString(state.IdentityPublicKey)
			if protocol.VerifyCredentialProof(proof, ed25519.PublicKey(public)) != nil {
				t.Error("invalid node recovery proof")
			}

			_ = json.NewEncoder(w).
				Encode(protocol.CredentialLease{DeviceID: "device", Credential: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: expiry})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)

			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store, err := localstate.Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()

	if err := RecoverCredential(
		t.Context(),
		server.Client(),
		server.URL,
		"network",
		&state,
	); err != nil {
		t.Fatal(err)
	}

	if state.IdentityPrivateKey != original.IdentityPrivateKey ||
		state.DeviceID != original.DeviceID ||
		state.WireGuard != original.WireGuard ||
		!state.CredentialExpiresAt.Equal(expiry) {
		t.Fatal("recovery changed identity or lost expiry")
	}

	if err := state.SaveTo(store); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFrom(store)
	if err != nil {
		t.Fatal(err)
	}

	if !loaded.CredentialExpiresAt.Equal(expiry) {
		t.Fatal("lease expiry not durable")
	}
}
