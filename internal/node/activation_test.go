package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestEnrollByInviteReusesStateKeysAndNeverTransmitsFragmentOrCode(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)
	state, err := NewState()
	if err != nil {
		t.Fatal(err)
	}
	original := state
	now := time.Now()
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, _ := invite.SignPermit(local.Permit, key, "root-1")
	ready := false
	polls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Fragment != "" || strings.Contains(r.URL.String(), local.Code) {
			t.Error("invite secret transmitted in URL")
		}
		switch {
		case r.URL.Path == "/api/v1/invites/proof":
			var input struct {
				Permit invite.SignedPermit `json:"permit"`
				Proof  invite.Proof        `json:"proof"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if err := invite.VerifyProofWithCode(
				input.Permit,
				input.Proof,
				"family",
				local.Code,
				now,
			); err != nil {
				t.Error(err)
			}
			if string(input.Proof.DevicePublicKey) != string(mustPublic(state.IdentityPublicKey)) {
				t.Error("identity replaced")
			}
			ready = true
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/challenge"):
			polls++
			if !ready || polls == 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).
				Encode(protocol.ClaimChallenge{Version: 1, NetworkID: "home", InviteID: local.Permit.InviteID, DeviceID: "linux", Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: time.Now().Add(time.Minute).Unix()})
		case strings.HasSuffix(r.URL.Path, "/claim"):
			var p protocol.ClaimProof
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				t.Error(err)
			}
			private, _ := base64.RawURLEncoding.DecodeString(state.IdentityPrivateKey)
			expected, _ := protocol.SignClaim(p.Challenge, ed25519.PrivateKey(private))
			if expected.Signature != p.Signature {
				t.Error("invalid possession proof")
			}
			_ = json.NewEncoder(w).
				Encode(map[string]any{"device": map[string]any{"credential_expires_at": time.Now().Add(15 * time.Minute), "id": "linux", "role": "client", "status": "active", "identity_public_key": state.IdentityPublicKey, "wireguard_public_key": state.WireGuard.PublicKey, "credential": base64.RawURLEncoding.EncodeToString(make([]byte, 32))}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	link, err := local.Link("https://control.example", permit)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.json")
	err = EnrollByInvite(
		context.Background(),
		server.Client(),
		InviteEnrollment{
			ControlURL:    server.URL,
			InviteLink:    link,
			Code:          local.Code,
			DeviceID:      "linux",
			StatePath:     path,
			RootPublicKey: root,
			NetworkID:     "home",
			PollInterval:  time.Millisecond,
		},
		&state,
	)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID != "linux" || loaded.DeviceCredential == "" ||
		loaded.IdentityPrivateKey != original.IdentityPrivateKey ||
		loaded.WireGuard.PrivateKey != original.WireGuard.PrivateKey {
		t.Fatal("identity or enrollment was not saved")
	}
}
func mustPublic(raw string) []byte { b, _ := base64.RawURLEncoding.DecodeString(raw); return b }
func TestPrepareInviteProofRejectsWrongRootAndMalformedFragment(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _, _ := ed25519.GenerateKey(rand.Reader)
	state, _ := NewState()
	now := time.Now()
	local, _ := invite.New("home", "family", time.Hour, now, rand.Reader)
	permit, _ := invite.SignPermit(local.Permit, key, "root-1")
	link, _ := local.Link("https://control.example", permit)
	for _, params := range []InviteEnrollment{{InviteLink: link, Code: local.Code, DeviceID: "linux", RootPublicKey: wrong, NetworkID: "home"}, {InviteLink: link, Code: local.Code, DeviceID: "linux", RootPublicKey: root, NetworkID: "other"}, {InviteLink: link + "&permit=bad", Code: local.Code, DeviceID: "linux", RootPublicKey: root, NetworkID: "home"}} {
		if _, _, err := PrepareInviteProof(params, state, now); err == nil {
			t.Fatal("untrusted invite accepted")
		}
	}
}
