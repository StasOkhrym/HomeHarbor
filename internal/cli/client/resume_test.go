package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	nodetest "github.com/StasOkhrym/homeharbor/internal/testutil/node"
)

func TestJoinResumesOnlyPreviouslyApprovedExistingIdentity(t *testing.T) {
	for _, mode := range []string{"approved expired", "pending", "missing approval time", "future approval", "approval after expiry", "wrong device", "wrong identity", "wrong tunnel", "wrong profile", "tampered permit", "tampered proof", "wrong record", "missing state"} {
		t.Run(mode, func(t *testing.T) {
			state, err := node.NewState()
			if err != nil {
				t.Fatal(err)
			}

			device, err := joinDeviceID(state.IdentityPublicKey)
			if err != nil {
				t.Fatal(err)
			}

			var record protocol.InviteRecord
			records, challenges, claims, submissions := 0, 0, 0, 0

			fixture := newJoinFixture(
				t,
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == http.MethodGet:
						records++
						_ = json.NewEncoder(w).Encode(record)
					case strings.HasSuffix(r.URL.Path, "/proof"):
						submissions++
						w.WriteHeader(http.StatusAccepted)
					case strings.HasSuffix(r.URL.Path, "/challenge"):
						challenges++
						_ = json.NewEncoder(w).
							Encode(protocol.ClaimChallenge{Version: 1, NetworkID: "home", InviteID: record.InviteID, DeviceID: device, Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: time.Now().Add(time.Minute).Unix()})
					case strings.HasSuffix(r.URL.Path, "/claim"):
						claims++
						var proof protocol.ClaimProof

						if json.NewDecoder(r.Body).Decode(&proof) != nil {
							t.Error("invalid claim JSON")
						}

						pub, _ := base64.RawURLEncoding.DecodeString(state.IdentityPublicKey)
						if protocol.VerifyClaim(proof, ed25519.PublicKey(pub)) != nil {
							t.Error("claim lacks existing identity possession")
						}

						_ = json.NewEncoder(w).Encode(struct {
							Device protocol.EnrolledDevice `json:"device"`
						}{protocol.EnrolledDevice{ID: device, Role: "client", Status: "active", IdentityPublicKey: state.IdentityPublicKey, WireGuardPublicKey: state.WireGuard.PublicKey, Credential: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), CredentialExpiresAt: time.Now().Add(10 * time.Minute)}})
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}),
			)
			issued := time.Now().Add(-2 * time.Hour)
			approved := issued.Add(30 * time.Minute)

			item, err := invite.New("home", "family", time.Hour, issued, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			permit, err := invite.SignPermit(item.Permit, fixture.signing, "root-1")
			if err != nil {
				t.Fatal(err)
			}

			link, err := item.Link(fixture.server.URL, permit)
			if err != nil {
				t.Fatal(err)
			}

			_, proof, err := node.PrepareInviteProof(
				node.InviteEnrollment{
					InviteLink:    link,
					Code:          item.Code,
					DeviceID:      device,
					RootPublicKey: fixture.root,
					NetworkID:     "home",
				},
				state,
				approved,
			)
			if err != nil {
				t.Fatal(err)
			}

			record = protocol.InviteRecord{
				InviteID:           item.Permit.InviteID,
				ProfileID:          "family",
				DeviceID:           device,
				DevicePublic:       proof.DevicePublicKey,
				WireGuardPublicKey: proof.WireGuardPublicKey,
				Permit:             permit,
				Proof:              proof,
				Status:             "approved",
				CreatedAt:          issued,
				ApprovedAt:         &approved,
			}
			requested := record.InviteID
			switch mode {
			case "pending":
				record.Status = "pending"
			case "missing approval time":
				record.ApprovedAt = nil
			case "future approval":
				future := time.Now().Add(time.Hour)
				record.ApprovedAt = &future
			case "approval after expiry":
				late := time.Now().Add(-time.Minute)
				record.ApprovedAt = &late
			case "wrong device":
				record.DeviceID = "another"
			case "wrong identity":
				record.DevicePublic = make([]byte, 32)
			case "wrong tunnel":
				record.WireGuardPublicKey = make([]byte, 32)
			case "wrong profile":
				record.ProfileID = "another"
			case "tampered permit":
				record.Permit.Signature = make([]byte, 64)
			case "tampered proof":
				record.Proof.Signature = make([]byte, 64)
			case "wrong record":
				record.InviteID = "another"
			}

			if mode != "missing state" {
				if err := nodetest.Save(state, fixture.state); err != nil {
					t.Fatal(err)
				}
			}

			command := NewCommand()

			command.SetIn(strings.NewReader(""))
			var out, errOut bytes.Buffer

			status := host.Execute(
				t.Context(),
				[]string{
					"join",
					"--resume-invite",
					requested,
					"--control",
					fixture.server.URL,
					"--ca-file",
					fixture.caPath,
					"--root-public-key",
					fixture.rootPath,
					"--network-id",
					"home",
					"--trust-fingerprint",
					trustFingerprint(fixture.root, "home"),
					"--state",
					fixture.state,
				},
				&out,
				&errOut,
				command,
			)
			if mode == "approved expired" {
				if status != 0 || records != 1 || challenges != 1 || claims != 1 ||
					submissions != 0 {
					t.Fatalf(
						"resume failed: exit=%d records=%d challenges=%d claims=%d submissions=%d stderr=%s",
						status,
						records,
						challenges,
						claims,
						submissions,
						errOut.String(),
					)
				}

				saved, e := nodetest.Load(fixture.state)

				if e != nil || saved.DeviceID != device || saved.DeviceCredential == "" ||
					saved.IdentityPrivateKey != state.IdentityPrivateKey ||
					saved.WireGuard != state.WireGuard {
					t.Fatal("resume lost identity or did not durably claim")
				}
			} else {
				expectedRecords := 1
				if mode == "missing state" {
					expectedRecords = 0
				}

				if status == 0 || records != expectedRecords || challenges != 0 || claims != 0 ||
					submissions != 0 {
					t.Fatalf(
						"invalid resume crossed claim boundary: exit=%d records=%d challenges=%d claims=%d",
						status,
						records,
						challenges,
						claims,
					)
				}

				if mode == "missing state" {
					if _, e := os.Stat(fixture.state); !os.IsNotExist(e) {
						t.Fatal("resume created replacement identity")
					}
				}
			}

			if strings.Contains(out.String()+errOut.String(), item.Code) ||
				strings.Contains(out.String()+errOut.String(), state.IdentityPrivateKey) {
				t.Fatal("resume printed private material")
			}
		})
	}
}
