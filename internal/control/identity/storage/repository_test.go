package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func TestPostgresRecoveryCodeConcurrentConsume(t *testing.T) {
	pool := identityTestPool(t)
	store := New(pool)

	hash := sha256.Sum256([]byte("single-use-code"))

	if err := store.SaveRecoveryCodes(
		context.Background(),
		identity.AccountScope{
			AccountID:   identity.OwnerAccountID,
			AuthVersion: 1,
			Purpose:     identity.SessionMigration,
		},
		[]identity.RecoveryCode{{Hash: hash, CreatedAt: time.Now().UTC()}},
	); err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()

			if store.ConsumeRecoveryCode(
				context.Background(),
				identity.RecoveryUse{
					Scope: identity.AccountScope{
						AccountID:   identity.OwnerAccountID,
						AuthVersion: 1,
						Purpose:     identity.SessionMigration,
					},
					Hash:   hash,
					UsedAt: time.Now().UTC(),
				},
			) == nil {
				successes.Add(1)
			}
		}()
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d", successes.Load())
	}
}

func identityTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	if err = migrations.Up(context.Background(), pool); err != nil {
		t.Fatal(err)
	}

	if _, err = pool.Exec(
		context.Background(),
		`TRUNCATE recovery_codes RESTART IDENTITY CASCADE`,
	); err != nil {
		t.Fatal(err)
	}

	return pool
}

func TestPostgresRecoveryCodesRemainAccountScoped(t *testing.T) {
	pool := identityTestPool(t)
	store := New(pool)
	suffix := fmt.Sprint(time.Now().UnixNano())
	left, right := "recovery-a-"+suffix, "recovery-b-"+suffix
	for _, id := range []string{left, right} {
		if _, err := pool.Exec(
			t.Context(),
			`INSERT INTO admin_accounts(account_id,role,status,user_handle,email,password_hash)VALUES($1,'admin','active',$2,$1||'@example.test','hash')`,
			id,
			[]byte(id),
		); err != nil {
			t.Fatal(err)
		}
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := pool.Exec(
			ctx,
			`DELETE FROM recovery_codes WHERE account_id=ANY($1)`,
			[]string{left, right},
		); err != nil {
			t.Error(err)
		}

		if _, err := pool.Exec(
			ctx,
			`DELETE FROM admin_accounts WHERE account_id=ANY($1)`,
			[]string{left, right},
		); err != nil {
			t.Error(err)
		}
	})
	now := time.Now().UTC()

	// Identical hashes may be scoped to separate accounts; consuming or replacing
	// either account's set must never affect the other one.
	shared := sha256.Sum256([]byte("same-test-code"))
	codes := []identity.RecoveryCode{{Hash: shared, CreatedAt: now}}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: left, AuthVersion: 1, Purpose: identity.SessionAdmin},
		codes,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: right, AuthVersion: 1, Purpose: identity.SessionAdmin},
		codes,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{
			Scope: identity.AccountScope{
				AccountID:   left,
				AuthVersion: 1,
				Purpose:     identity.SessionAdmin,
			},
			Hash:   shared,
			UsedAt: now,
		},
	); err != nil {
		t.Fatal(err)
	}

	if err := store.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{
			Scope: identity.AccountScope{
				AccountID:   right,
				AuthVersion: 1,
				Purpose:     identity.SessionAdmin,
			},
			Hash:   shared,
			UsedAt: now,
		},
	); err != nil {
		t.Fatal("one account consumed another account's code")
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: right, AuthVersion: 1, Purpose: identity.SessionAdmin},
		codes,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: left, AuthVersion: 1, Purpose: identity.SessionAdmin},
		nil,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{
			Scope: identity.AccountScope{
				AccountID:   right,
				AuthVersion: 1,
				Purpose:     identity.SessionAdmin,
			},
			Hash:   shared,
			UsedAt: now,
		},
	); err != nil {
		t.Fatal("replacement deleted another account's code")
	}
}

func TestPostgresBootstrapCannotAttachKeyToConfiguredOwner(t *testing.T) {
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET status='active',email='owner@example.test',password_hash='hash' WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	store := New(pool)

	err := store.SaveBootstrapCredential(
		t.Context(),
		[]byte("homeharbor-admin-v1"),
		webauthn.Credential{
			ID:              []byte("unapproved-key"),
			PublicKey:       []byte("public"),
			AttestationType: "none",
		},
	)

	if !errors.Is(err, identity.ErrBootstrapClosed) {
		t.Fatalf("configured owner accepted a bootstrap key: %v", err)
	}
}
