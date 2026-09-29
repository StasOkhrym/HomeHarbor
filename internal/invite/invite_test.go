package invite

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestInviteProofBindsCodeAndDevice(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	invite, err := New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermit(invite.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPermit(permit, rootPublic, "home", now); err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := invite.Proof("device-1", devicePrivate, invite.Code)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyProofWithCode(permit, proof, "family", invite.Code, now); err != nil {
		t.Fatal(err)
	}
	if err = VerifyProofWithCode(permit, proof, "other", invite.Code, now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong profile error=%v", err)
	}
	wrongCode := proof
	wrongCode.CodeDigest = []byte("wrong")
	if err = VerifyProofWithCode(permit, wrongCode, "family", invite.Code, now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("wrong code proof accepted: %v", err)
	}
}

func TestProofRequiresDevicePrivateKey(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	item, err := New("home", "family", time.Minute, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermit(item.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := item.Proof("device-1", devicePrivate, item.Code)
	if err != nil {
		t.Fatal(err)
	}
	proof.DevicePublicKey = otherPublic
	if err := VerifyProofWithCode(permit, proof, "family", item.Code, now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("proof with mismatched device key error = %v", err)
	}
	_ = rootPublic
}

func TestProofRejectsEmptyDeviceID(t *testing.T) {
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	item, err := New("home", "family", time.Minute, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermit(item.Permit, rootPrivate, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	_, devicePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := item.Proof("device-1", devicePrivate, item.Code)
	if err != nil {
		t.Fatal(err)
	}
	proof.DeviceID = ""
	if err := VerifyProof(permit, proof, "family", now); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("VerifyProof() error = %v", err)
	}
	_ = rootPublic
}

func TestPermitRejectsTamperingAndExpiry(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	invite, err := New("home", "family", time.Minute, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := SignPermit(invite.Permit, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	permit.Payload[len(permit.Payload)-1] ^= 1
	if err = VerifyPermit(permit, publicKey, "home", now); !errors.Is(err, ErrInvalidPermit) {
		t.Fatalf("tampered permit error=%v", err)
	}
	permit, err = SignPermit(invite.Permit, privateKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyPermit(permit, publicKey, "home", now.Add(2*time.Minute)); !errors.Is(err, ErrExpiredInvite) {
		t.Fatalf("expired permit error=%v", err)
	}
}

func TestApprovalBindsExactDeviceDiff(t *testing.T) {
	_, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval := Approval{Version: Version, InviteID: "invite-1", ProfileID: "family", DeviceID: "phone-1", DevicePublicKey: make([]byte, ed25519.PublicKeySize)}
	signed, err := SignApproval(approval, rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := rootPrivate.Public().(ed25519.PublicKey)
	if err := VerifyApproval(signed, publicKey, approval); err != nil {
		t.Fatal(err)
	}
	approval.DeviceID = "other-phone"
	if err := VerifyApproval(signed, publicKey, approval); !errors.Is(err, ErrInvalidApproval) {
		t.Fatalf("modified approval error = %v", err)
	}
}
