package invites

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/invite"
)

func TestInviteProofIsPendingUntilTrustedCompanionApproves(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Proof("phone-1", devicePrivate, local.Code)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewMemoryStore(), rootPublic, "home", func() time.Time { return now })
	if err = service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Approve(context.Background(), local.Permit.InviteID, "wrong"); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong code error=%v", err)
	}
	approved, err := service.Approve(context.Background(), local.Permit.InviteID, local.Code)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusApproved || approved.DeviceID != "phone-1" {
		t.Fatalf("approved=%#v", approved)
	}
	if _, err = service.Approve(context.Background(), local.Permit.InviteID, local.Code); !errors.Is(err, ErrInviteConsumed) {
		t.Fatalf("reused invite error=%v", err)
	}
}

func TestSignedApprovalAcceptsOnlyPendingExactDiff(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := local.Proof("phone-1", devicePrivate, local.Code)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewMemoryStore(), rootPublic, "home", func() time.Time { return now })
	if err := service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	approval, err := invite.SignApproval(invite.Approval{Version: invite.Version, InviteID: local.Permit.InviteID, ProfileID: "family", DeviceID: "phone-1", DevicePublicKey: proof.DevicePublicKey}, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.ApproveSigned(context.Background(), approval)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusApproved {
		t.Fatalf("approved status = %q", approved.Status)
	}
}
