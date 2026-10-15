package node_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestInvitePollingPreservesOnboardingBudgetAndHonorsCooldown(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		retryAfter string
		interval   time.Duration
	}{
		{"default pending", http.StatusConflict, "", 0},
		{"server cooldown", http.StatusTooManyRequests, "2", time.Millisecond},
		{"missing cooldown", http.StatusTooManyRequests, "", time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, signing, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			state, err := node.NewState()
			if err != nil {
				t.Fatal(err)
			}

			item, err := invite.New("home", "family", time.Hour, time.Now(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			permit, err := invite.SignPermit(item.Permit, signing, "root-1")
			if err != nil {
				t.Fatal(err)
			}

			link, err := item.Link("https://control.example", permit)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			var polls atomic.Int32
			first := make(chan struct{})
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/api/v1/invites/proof" {
						w.WriteHeader(http.StatusAccepted)
						return
					}
					if strings.HasSuffix(r.URL.Path, "/challenge") {
						if polls.Add(1) == 1 {
							close(first)
						}

						if tc.retryAfter != "" {
							w.Header().Set("Retry-After", tc.retryAfter)
						}

						w.WriteHeader(tc.status)
						return
					}

					t.Error("unexpected onboarding operation")

					w.WriteHeader(http.StatusNotFound)
				}),
			)
			defer server.Close()

			path := filepath.Join(t.TempDir(), "state.json")

			store, err := localstate.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = store.Close() }()

			done := make(chan error, 1)
			go func() {
				done <- node.EnrollByInviteFrom(ctx, server.Client(), node.InviteEnrollment{
					ControlURL: server.URL, InviteLink: link, Code: item.Code,
					DeviceID: "linux", StatePath: path, RootPublicKey: root,
					NetworkID: "home", PollInterval: tc.interval,
				}, &state, store)
			}()
			select {
			case <-first:
			case err := <-done:
				t.Fatalf("join ended before first challenge: %v", err)
			case <-time.After(5 * time.Second):
				cancel()
				<-done

				t.Fatal("first challenge did not start")
			}

			// Cancellation during the cooldown must interrupt immediately. The
			// previous one-second/default and millisecond/429 loops both retry
			// inside this observation, starving the shared 10/minute budget.
			timer := time.AfterFunc(1200*time.Millisecond, cancel)
			defer timer.Stop()

			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("cooldown cancellation: %v", err)
			}

			if got := polls.Load(); got != 1 {
				t.Fatalf("retried during pending/cooldown: %d challenges", got)
			}

			if state.DeviceCredential != "" || state.DeviceID != "" {
				t.Fatal("waiting client obtained a credential")
			}
		})
	}
}

func TestEnrollByInviteReusesStateKeysAndNeverTransmitsFragmentOrCode(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)

	state, err := node.NewState()
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

	store, err := localstate.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = store.Close() })

	err = node.EnrollByInviteFrom(
		context.Background(),
		server.Client(),
		node.InviteEnrollment{
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
		store,
	)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := node.LoadFrom(store)
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
	state, _ := node.NewState()
	now := time.Now()
	local, _ := invite.New("home", "family", time.Hour, now, rand.Reader)

	permit, _ := invite.SignPermit(local.Permit, key, "root-1")

	link, _ := local.Link("https://control.example", permit)
	for _, params := range []node.InviteEnrollment{{InviteLink: link, Code: local.Code, DeviceID: "linux", RootPublicKey: wrong, NetworkID: "home"}, {InviteLink: link, Code: local.Code, DeviceID: "linux", RootPublicKey: root, NetworkID: "other"}, {InviteLink: link + "&permit=bad", Code: local.Code, DeviceID: "linux", RootPublicKey: root, NetworkID: "home"}} {
		if _, _, err := node.PrepareInviteProof(params, state, now); err == nil {
			t.Fatal("untrusted invite accepted")
		}
	}
}
