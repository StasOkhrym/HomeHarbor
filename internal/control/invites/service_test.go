package invites

import (
	"bytes"
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
	proof, err := local.Proof("phone-1", devicePrivate, local.Code, bytes.Repeat([]byte{1}, 32))
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
	proof, err := local.Proof("phone-1", devicePrivate, local.Code, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(NewMemoryStore(), rootPublic, "home", func() time.Time { return now })
	if err := service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	approval, err := invite.SignApproval(invite.Approval{Version: invite.Version, InviteID: local.Permit.InviteID, ProfileID: "family", DeviceID: "phone-1", DevicePublicKey: proof.DevicePublicKey, WireGuardPublicKey: proof.WireGuardPublicKey}, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := service.ApproveSigned(context.Background(), approval)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Record.Status != StatusApproved {
		t.Fatalf("approved status = %q", approved.Record.Status)
	}
}

func TestSignedApprovalActivatesDeviceWithOneTimeCredential(t *testing.T) {
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
	proof, err := local.Proof("phone-1", devicePrivate, local.Code, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	service := NewService(store, rootPublic, "home", func() time.Time { return now }, WithActivator(store), WithRandom(bytes.NewReader(bytes.Repeat([]byte{9}, 32))))
	if err := service.SubmitProof(context.Background(), permit, proof); err != nil {
		t.Fatal(err)
	}
	approval, err := invite.SignApproval(invite.Approval{Version: invite.Version, InviteID: local.Permit.InviteID, ProfileID: "family", DeviceID: "phone-1", DevicePublicKey: proof.DevicePublicKey, WireGuardPublicKey: proof.WireGuardPublicKey}, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.ApproveSigned(context.Background(), approval)
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Status != StatusApproved || result.Device.Status != "active" || result.Device.Credential == "" {
		t.Fatalf("activation result=%#v", result)
	}
	if stored := store.devices["phone-1"]; stored.Credential != "" || stored.CredentialHash == [32]byte{} {
		t.Fatalf("store retained or missed credential hash: %#v", stored)
	}
	if _, err := service.ApproveSigned(context.Background(), approval); !errors.Is(err, ErrInviteConsumed) {
		t.Fatalf("replayed approval error=%v", err)
	}
}
