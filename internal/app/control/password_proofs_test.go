package control

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestRedisRuntimeEnrollmentProofCannotEnterNormalLoginNamespace(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL required")
	}

	options, err := redisclient.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })

	stores, err := newPasswordProofStores(
		client,
		"test:runtime-proof:"+uuid.NewString(),
		time.Now,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	record := identity.Preauth{
		Hash:        sha256.Sum256([]byte("opaque-test-password-proof")),
		AccountID:   "invited-account",
		AuthVersion: 3,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	}

	if err := stores.enrollment.SavePreauth(t.Context(), record); err != nil {
		t.Fatal(err)
	}

	if _, err := stores.login.ReadPreauth(
		t.Context(),
		record.Hash,
		now,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("runtime setup proof entered normal namespace", err)
	}

	other := record
	other.AccountID = "active-account"

	if err := stores.login.SavePreauth(t.Context(), other); err != nil {
		t.Fatal("normal namespace collided with enrollment", err)
	}

	setup, err := stores.enrollment.ReadPreauth(t.Context(), record.Hash, now)

	if err != nil || setup.AccountID != record.AccountID {
		t.Fatal("normal proof replaced setup authority", err)
	}

	normal, err := stores.login.ReadPreauth(t.Context(), record.Hash, now)

	if err != nil || normal.AccountID != other.AccountID {
		t.Fatal("normal authority was not independent", err)
	}
}
