package storage

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func totpSQLFixture(
	t *testing.T,
	withPasskey bool,
) (*Repository, *Repository, *pgxpool.Pool, identity.AccountScope, identity.TOTPRecord, time.Time) {
	t.Helper()
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(other.Close)
	store, replica := New(pool), New(other)
	if withPasskey {
		if err := store.SaveBootstrapCredential(
			t.Context(),
			[]byte("homeharbor-admin-v1"),
			webauthn.Credential{
				ID:              []byte("owner-key"),
				PublicKey:       []byte("public"),
				AttestationType: "none",
			},
		); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET status='active',email='owner@example.test',password_hash='private-hash',auth_version=3 WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	box, err := sealed.New(bytes.Repeat([]byte{7}, 32), "identity.totp")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.Seal(identity.OwnerAccountID, []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(2000000000, 0).UTC()
	scope := identity.AccountScope{
		AccountID:   identity.OwnerAccountID,
		AuthVersion: 3,
		Purpose:     identity.SessionAdmin,
	}
	record := identity.TOTPRecord{
		ID:                uuid.NewString(),
		AccountID:         scope.AccountID,
		EnrollmentVersion: 3,
		Ciphertext:        ciphertext,
		CreatedAt:         now,
		ExpiresAt:         now.Add(10 * time.Minute),
		LastStep:          -1,
	}

	return store, replica, pool, scope, record, now
}

func TestPostgresTOTPConfirmationAndStepAreOneUseAcrossPools(t *testing.T) {
	store, replica, _, scope, record, now := totpSQLFixture(t, false)

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	var confirmed atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			if err := replica.ConfirmTOTP(
				t.Context(),
				scope,
				record.ID,
				66666666,
				now,
			); err == nil {
				confirmed.Add(1)
			} else if !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if confirmed.Load() != 1 {
		t.Fatalf("confirmations=%d", confirmed.Load())
	}

	account, err := store.Account(t.Context(), scope.AccountID)

	if err != nil || account.AuthVersion != 4 {
		t.Fatal("confirmation did not invalidate sessions", err)
	}

	if err := replica.ConsumeTOTP(
		t.Context(),
		scope,
		record.ID,
		66666667,
		now.Add(30*time.Second),
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale password proof consumed next code", err)
	}

	scope.AuthVersion = 4
	var consumed atomic.Int32
	for range 12 {
		group.Go(func() {
			if err := store.ConsumeTOTP(
				t.Context(),
				scope,
				record.ID,
				66666667,
				now.Add(30*time.Second),
			); err == nil {
				consumed.Add(1)
			} else if !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if consumed.Load() != 1 {
		t.Fatalf("step consumes=%d", consumed.Load())
	}

	stored, err := replica.TOTP(t.Context(), scope.AccountID)

	if err != nil || stored.LastStep != 66666667 || stored.ConfirmedAt == nil {
		t.Fatalf("wrong committed TOTP: %+v %v", stored, err)
	}
}

func TestPostgresTOTPResetAndReplacementFencePendingEnrollment(t *testing.T) {
	for _, change := range []string{"password-reset", "replacement", "expiry", "clock-backward"} {
		t.Run(change, func(t *testing.T) {
			store, replica, pool, scope, record, now := totpSQLFixture(t, false)
			if change == "expiry" {
				record.ExpiresAt = now.Add(-time.Second)
				record.CreatedAt = now.Add(-10 * time.Minute)
			}

			if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
				t.Fatal(err)
			}

			switch change {
			case "clock-backward":
				now = now.Add(-time.Second)
			case "password-reset":
				if _, err := pool.Exec(
					t.Context(),
					`UPDATE admin_accounts SET auth_version=4 WHERE account_id=$1`,
					scope.AccountID,
				); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				replacement := record
				replacement.ID = uuid.NewString()

				if err := replica.SavePendingTOTP(t.Context(), scope, replacement); err != nil {
					t.Fatal(err)
				}
			}

			if err := store.ConfirmTOTP(
				t.Context(),
				scope,
				record.ID,
				66666666,
				now,
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatalf("%s admitted obsolete enrollment: %v", change, err)
			}

			if change == "password-reset" {
				scope.AuthVersion = 4

				if err := replica.ConfirmTOTP(
					t.Context(),
					scope,
					record.ID,
					66666666,
					now,
				); !errors.Is(
					err,
					identity.ErrInvalidCredential,
				) {
					t.Fatal("new password proof resurrected old pending seed", err)
				}
			}
		})
	}
}

func TestPostgresTOTPRemovalPreservesLastFactor(t *testing.T) {
	for _, withPasskey := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "last-factor", true: "alternate-passkey"}[withPasskey],
			func(t *testing.T) {
				store, replica, _, scope, record, now := totpSQLFixture(t, withPasskey)

				if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
					t.Fatal(err)
				}

				if err := store.ConfirmTOTP(
					t.Context(),
					scope,
					record.ID,
					66666666,
					now,
				); err != nil {
					t.Fatal(err)
				}

				scope.AuthVersion = 4

				err := replica.RemoveTOTP(t.Context(), scope)
				if !withPasskey {
					if !errors.Is(err, identity.ErrLastMFA) {
						t.Fatal("last factor removed", err)
					}

					if _, err := store.TOTP(t.Context(), scope.AccountID); err != nil {
						t.Fatal("rejected removal deleted factor", err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}

					if _, err := store.TOTP(
						t.Context(),
						scope.AccountID,
					); !errors.Is(
						err,
						identity.ErrInvalidCredential,
					) {
						t.Fatal("removed TOTP remained present", err)
					}

					if _, err := store.Credential(
						t.Context(),
						[]byte("homeharbor-admin-v1"),
						[]byte("owner-key"),
					); err != nil {
						t.Fatal("TOTP removal deleted alternate passkey", err)
					}
				}
			},
		)
	}
}

func TestPostgresTOTPRejectsIncoherentSeedState(t *testing.T) {
	_, _, pool, scope, record, now := totpSQLFixture(t, false)
	tooLong := now.Add(11 * time.Minute)
	for _, tc := range []struct {
		name               string
		expires, confirmed *time.Time
		step               int64
	}{
		{name: "missing-expiry", step: -1}, {name: "missing-confirmation", step: 0}, {name: "unbounded-pending", expires: &tooLong, step: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(t.Context()) }()

			_, err = tx.Exec(
				t.Context(),
				`INSERT INTO admin_totp(account_id,totp_id,enrollment_auth_version,seed_ciphertext,created_at,pending_expires_at,confirmed_at,last_used_step)VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
				scope.AccountID,
				record.ID,
				scope.AuthVersion,
				record.Ciphertext,
				record.CreatedAt,
				tc.expires,
				tc.confirmed,
				tc.step,
			)
			var constraint interface{ SQLState() string }

			if !errors.As(err, &constraint) || constraint.SQLState() != "23514" {
				t.Fatalf("incoherent state admitted or wrong failure: %v", err)
			}
		})
	}
}
