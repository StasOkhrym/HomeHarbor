package companion

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	memoryinvites "github.com/StasOkhrym/homeharbor/internal/testutil/control/invites"
)

// This boundary fixture exercises companion validation; transactional module
// writes and idempotency are tested against actual PostgreSQL separately.
type approvalFixture struct {
	store *memoryinvites.Repository
	root  ed25519.PublicKey
}

func (f approvalFixture) ApproveSigned(
	ctx context.Context,
	signed invite.SignedApproval,
) (invites.ApprovalResult, error) {
	var a invite.Approval

	if err := cbor.Unmarshal(signed.Payload, &a); err != nil {
		return invites.ApprovalResult{}, err
	}

	r, err := f.store.Get(ctx, a.InviteID)
	if err != nil {
		return invites.ApprovalResult{}, err
	}

	if err := invite.VerifyApproval(
		signed,
		f.root,
		invite.Approval{
			Version:            1,
			InviteID:           r.InviteID,
			ProfileID:          r.ProfileID,
			DeviceID:           r.DeviceID,
			DevicePublicKey:    r.DevicePublic,
			WireGuardPublicKey: r.WireGuardPublicKey,
		},
	); err != nil {
		return invites.ApprovalResult{}, err
	}

	if r.Status == invites.StatusPending {
		r, err = f.store.Approve(ctx, r.InviteID, time.Now())
		if err != nil {
			return invites.ApprovalResult{}, err
		}
	}

	if r.Status != invites.StatusApproved {
		return invites.ApprovalResult{}, invites.ErrInviteConsumed
	}

	return invites.ApprovalResult{
		Record:    r,
		InviteID:  r.InviteID,
		DeviceID:  r.DeviceID,
		ProfileID: r.ProfileID,
		Status:    r.Status,
	}, nil
}

func TestCompanionRetriesApprovedRecordAfterPermitExpiry(t *testing.T) {
	root, key, _ := ed25519.GenerateKey(rand.Reader)

	_, device, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now().UTC()
	local, _ := invite.New("home", "family", time.Minute, now, rand.Reader)

	permit, _ := invite.SignPermit(local.Permit, key, "root-1")

	proof, _ := local.Proof("linux", device, local.Code, bytes.Repeat([]byte{7}, 32))
	r := invites.Record{
		InviteID:           proof.InviteID,
		ProfileID:          "family",
		DeviceID:           "linux",
		DevicePublic:       proof.DevicePublicKey,
		WireGuardPublicKey: proof.WireGuardPublicKey,
		Permit:             permit,
		Proof:              proof,
		Status:             invites.StatusApproved,
		ApprovedAt:         &now,
	}
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(r)
				return
			}

			var input struct {
				Approval invite.SignedApproval `json:"approval"`
			}

			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Error(err)
			}

			if err := invite.VerifyApproval(
				input.Approval,
				root,
				invite.Approval{
					Version:            1,
					InviteID:           r.InviteID,
					ProfileID:          r.ProfileID,
					DeviceID:           r.DeviceID,
					DevicePublicKey:    r.DevicePublic,
					WireGuardPublicKey: r.WireGuardPublicKey,
				},
			); err != nil {
				t.Error(err)
			}

			_ = json.NewEncoder(w).
				Encode(invites.ApprovalResult{InviteID: r.InviteID, DeviceID: r.DeviceID, ProfileID: r.ProfileID, Status: invites.StatusApproved})
		}),
	)
	defer server.Close()

	a := RemoteApprover{Endpoint: server.URL, Now: func() time.Time { return now.Add(time.Hour) }}

	if err := a.Approve(context.Background(), r.InviteID, local.Code, key); err != nil {
		t.Fatal("approved retry failed:", err)
	}
}

func TestCompanionRejectsApprovalCredentialResponse(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)

	_, device, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	local, _ := invite.New("home", "family", time.Hour, now, rand.Reader)

	permit, _ := invite.SignPermit(local.Permit, key, "root-1")

	proof, _ := local.Proof("linux", device, local.Code, bytes.Repeat([]byte{7}, 32))
	r := invites.Record{
		InviteID:           proof.InviteID,
		ProfileID:          "family",
		DeviceID:           "linux",
		DevicePublic:       proof.DevicePublicKey,
		WireGuardPublicKey: proof.WireGuardPublicKey,
		Permit:             permit,
		Proof:              proof,
		Status:             invites.StatusPending,
	}
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(r)
				return
			}

			_, _ = w.Write([]byte(`{"device":{"credential":"secret"}}`))
		}),
	)
	defer server.Close()

	err := (RemoteApprover{Endpoint: server.URL}).Approve(
		context.Background(),
		r.InviteID,
		local.Code,
		key,
	)

	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe approval response accepted or echoed: %v", err)
	}
}
