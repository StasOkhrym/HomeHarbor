package devices_test

import (
	"context"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/devices"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

func TestMemoryEnrollmentConflictPreservesTokenAndExistingCredential(t *testing.T) {
	ctx := context.Background()
	store := memorystore.NewRepository()
	now := time.Now()
	hash := [32]byte{1}

	if err := store.SeedDevice(
		ctx,
		domainpkg.Device{
			ID:                 "existing",
			IdentityPublicKey:  "ed",
			WireGuardPublicKey: "wg",
			CredentialHash:     [32]byte{2},
			Status:             domainpkg.StatusActive,
			CreatedAt:          now,
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveEnrollmentToken(
		ctx,
		domainpkg.EnrollmentToken{
			Hash:      hash,
			Role:      domainpkg.RoleClient,
			ExpiresAt: now.Add(time.Hour),
		},
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Enroll(
		ctx,
		hash,
		now,
		domainpkg.Device{ID: "new", IdentityPublicKey: "ed", WireGuardPublicKey: "new-wg"},
	); err == nil {
		t.Fatal("identity collision accepted")
	}

	if _, err := store.Enroll(
		ctx,
		hash,
		now,
		domainpkg.Device{
			ID:                 "new",
			IdentityPublicKey:  "new-ed",
			WireGuardPublicKey: "new-wg",
			CreatedAt:          now,
		},
	); err != nil {
		t.Fatal("failed enrollment consumed token:", err)
	}

	if _, err := store.AuthenticateCredential(ctx, [32]byte{2}, now); err != nil {
		t.Fatal("existing credential lost:", err)
	}
}
