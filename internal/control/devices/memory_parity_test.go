package devices_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

func TestCancelledContextReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()

	_, err := memorystore.NewRepository().ListDevices(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ListDevices error = %v", err)
	}
}

func TestListDevicesMatchesSQLOrdering(t *testing.T) {
	store := memorystore.NewRepository()
	for _, device := range []devices.Device{
		{ID: "z", IdentityPublicKey: "ed-z", WireGuardPublicKey: "wg-z", CredentialHash: [32]byte{1}, CreatedAt: time.Unix(2, 0)},
		{ID: "b", IdentityPublicKey: "ed-b", WireGuardPublicKey: "wg-b", CredentialHash: [32]byte{2}, CreatedAt: time.Unix(1, 0)},
		{ID: "a", IdentityPublicKey: "ed-a", WireGuardPublicKey: "wg-a", CredentialHash: [32]byte{3}, CreatedAt: time.Unix(1, 0)},
	} {
		if err := store.SeedDevice(context.Background(), device); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 || got[0].ID != "a" || got[1].ID != "b" || got[2].ID != "z" {
		t.Fatalf("device order = %#v", got)
	}
}

func TestEnrollmentTokenHashCannotBeReissued(t *testing.T) {
	store := memorystore.NewRepository()
	ctx := context.Background()

	now := time.Unix(1_800_000_000, 0)
	token := devices.EnrollmentToken{
		Hash:      [32]byte{1},
		Role:      devices.RoleClient,
		ExpiresAt: now.Add(time.Hour),
	}

	if err := store.SaveEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveEnrollmentToken(ctx, token); err == nil {
		t.Fatal("duplicate token hash accepted")
	}

	first := devices.Device{
		ID:                 "first",
		IdentityPublicKey:  "ed-first",
		WireGuardPublicKey: "wg-first",
		CredentialHash:     [32]byte{2},
		Status:             devices.StatusActive,
	}

	if _, err := store.Enroll(ctx, token.Hash, now, first); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveEnrollmentToken(ctx, token); err == nil {
		t.Fatal("consumed token hash reissued")
	}

	second := devices.Device{
		ID:                 "second",
		IdentityPublicKey:  "ed-second",
		WireGuardPublicKey: "wg-second",
		CredentialHash:     [32]byte{3},
		Status:             devices.StatusActive,
	}

	if _, err := store.Enroll(
		ctx,
		token.Hash,
		now,
		second,
	); !errors.Is(
		err,
		devices.ErrInvalidEnrollmentToken,
	) {
		t.Fatalf("replayed token enrollment = %v", err)
	}
}

func TestCredentialHashCollisionPreservesEnrollmentAndAuthentication(t *testing.T) {
	store := memorystore.NewRepository()
	ctx := context.Background()

	now := time.Unix(1_800_000_000, 0)
	first := devices.Device{
		ID:                  "first",
		IdentityPublicKey:   "ed-first",
		WireGuardPublicKey:  "wg-first",
		CredentialHash:      [32]byte{1},
		CredentialExpiresAt: now.Add(time.Hour),
		Status:              devices.StatusActive,
	}

	if err := store.SeedDevice(ctx, first); err != nil {
		t.Fatal(err)
	}

	second := devices.Device{
		ID:                  "second",
		IdentityPublicKey:   "ed-second",
		WireGuardPublicKey:  "wg-second",
		CredentialHash:      first.CredentialHash,
		CredentialExpiresAt: now.Add(time.Hour),
		Status:              devices.StatusActive,
	}

	if err := store.SeedDevice(ctx, second); !errors.Is(err, devices.ErrDeviceConflict) {
		t.Fatalf("duplicate seeded credential = %v", err)
	}

	token := devices.EnrollmentToken{
		Hash:      [32]byte{9},
		Role:      devices.RoleClient,
		ExpiresAt: now.Add(time.Hour),
	}

	if err := store.SaveEnrollmentToken(ctx, token); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Enroll(
		ctx,
		token.Hash,
		now,
		second,
	); !errors.Is(
		err,
		devices.ErrDeviceConflict,
	) {
		t.Fatalf("duplicate enrolled credential = %v", err)
	}

	second.CredentialHash = [32]byte{2}

	if _, err := store.Enroll(ctx, token.Hash, now, second); err != nil {
		t.Fatalf("failed enrollment consumed token: %v", err)
	}

	if err := store.RotateCredential(
		ctx,
		"second",
		second.CredentialHash,
		first.CredentialHash,
		now,
		now.Add(time.Hour),
	); !errors.Is(
		err,
		devices.ErrDeviceConflict,
	) {
		t.Fatalf("duplicate rotated credential = %v", err)
	}

	for _, check := range []struct {
		hash [32]byte
		id   string
	}{{first.CredentialHash, "first"}, {second.CredentialHash, "second"}} {
		got, err := store.AuthenticateCredential(ctx, check.hash, now)

		if err != nil || got.ID != check.id {
			t.Fatalf("credential %x resolved to %q, err=%v", check.hash, got.ID, err)
		}
	}

	if err := store.RotateCredential(
		ctx,
		"first",
		first.CredentialHash,
		[32]byte{3},
		now,
		now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}

	third := devices.Device{
		ID:                 "third",
		IdentityPublicKey:  "ed-third",
		WireGuardPublicKey: "wg-third",
		CredentialHash:     first.CredentialHash,
	}

	if err := store.SeedDevice(ctx, third); !errors.Is(err, devices.ErrDeviceConflict) {
		t.Fatalf("historical credential hash reused = %v", err)
	}
}
