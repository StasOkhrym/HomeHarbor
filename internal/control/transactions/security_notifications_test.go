package transactions_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	transactionpg "github.com/StasOkhrym/homeharbor/internal/control/transactions"
	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

func TestPostgresMFAChangesQueueOnlySealedSecurityNotices(t *testing.T) {
	_, reader, pool, codec, owner, now := accountMailFixture(t)
	store := transactionpg.NewIdentityWithNotifications(
		pool,
		codec,
		func() time.Time { return *now },
	)
	scope := identity.AccountScope{
		AccountID:   owner.AccountID,
		AuthVersion: 1,
		Purpose:     identity.SessionAdmin,
	}
	first := identity.NamedCredential{
		Name:      "First key",
		CreatedAt: *now,
		Credential: webauthn.Credential{
			ID:              []byte("first-key"),
			PublicKey:       []byte("public"),
			AttestationType: "none",
		},
	}

	if err := store.SavePersonalCredential(t.Context(), scope, first); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++
	codes := []identity.RecoveryCode{
		{Hash: sha256.Sum256([]byte("PRIVATE_RECOVERY_CODE")), CreatedAt: *now},
	}

	if err := store.SaveRecoveryCodes(t.Context(), scope, codes); err != nil {
		t.Fatal(err)
	}

	second := first
	second.Name = "Second key"
	second.Credential.ID = []byte("second-key")

	if err := store.SavePersonalCredential(t.Context(), scope, second); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++

	if err := store.RemovePasskey(t.Context(), scope, first.Credential.ID); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++

	if err := store.RemovePasskey(
		t.Context(),
		scope,
		second.Credential.ID,
	); !errors.Is(
		err,
		identity.ErrLastMFA,
	) {
		t.Fatal("last-key guard changed", err)
	}

	box, err := sealed.New(bytes.Repeat([]byte{7}, 32), "identity.totp")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.Seal(scope.AccountID, []byte("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}

	record := identity.TOTPRecord{
		ID:                uuid.NewString(),
		AccountID:         scope.AccountID,
		EnrollmentVersion: scope.AuthVersion,
		Ciphertext:        ciphertext,
		CreatedAt:         *now,
		ExpiresAt:         now.Add(10 * time.Minute),
		LastStep:          -1,
	}

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	if err := store.ConfirmTOTP(t.Context(), scope, record.ID, now.Unix()/30, *now); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++

	if err := store.RemoveTOTP(t.Context(), scope); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++

	account, err := reader.Account(t.Context(), owner.AccountID)

	if err != nil || account.AuthVersion != scope.AuthVersion {
		t.Fatal("notice wrapper lost account epoch", err)
	}

	var count int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE kind='security_notice' AND status='pending'`).
		Scan(&count); err != nil ||
		count != 6 {
		t.Fatal("missing notice or rejected write queued one", err, count)
	}

	var payload []byte

	if err := pool.QueryRow(t.Context(), `SELECT private_payload FROM notification_deliveries LIMIT 1`).
		Scan(&payload); err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(payload, []byte(owner.Email)) ||
		bytes.Contains(payload, []byte("PRIVATE_RECOVERY_CODE")) {
		t.Fatal("notice persisted private plaintext")
	}

	// All notices use one fixed safe template, without operation input/seeds/codes.
	rows, err := pool.Query(
		t.Context(),
		`SELECT id::text,account_id,kind,private_payload,logical_fingerprint,created_at,expires_at FROM notification_deliveries`,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	for rows.Next() {
		var prepared notifications.Prepared
		var fingerprint []byte

		if err := rows.Scan(
			&prepared.ID,
			&prepared.AccountID,
			&prepared.Kind,
			&prepared.Ciphertext,
			&fingerprint,
			&prepared.CreatedAt,
			&prepared.ExpiresAt,
		); err != nil {
			t.Fatal(err)
		}

		copy(prepared.Fingerprint[:], fingerprint)

		message, err := codec.Render(prepared, *now)

		if err != nil || message.To != owner.Email ||
			strings.Contains(message.Text, "PRIVATE_RECOVERY_CODE") ||
			strings.Contains(message.Text, "12345678901234567890") {
			t.Fatal("notice exposed MFA input or recipient changed", err)
		}
	}

	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresMFASettingRollsBackWhenNoticeQueueFails(t *testing.T) {
	for _, scenario := range []string{"passkey", "totp", "recovery"} {
		t.Run(scenario, func(t *testing.T) {
			_, reader, pool, codec, owner, now := accountMailFixture(t)
			store := transactionpg.NewIdentityWithNotifications(
				pool,
				codec,
				func() time.Time { return *now },
			)
			scope := identity.AccountScope{
				AccountID:   owner.AccountID,
				AuthVersion: 1,
				Purpose:     identity.SessionAdmin,
			}
			var mutate func(context.Context) error

			oldHash := sha256.Sum256([]byte("old-private-code"))
			switch scenario {
			case "passkey":
				key := identity.NamedCredential{
					Name:      "Retry key",
					CreatedAt: *now,
					Credential: webauthn.Credential{
						ID:              []byte("retry-key"),
						PublicKey:       []byte("public"),
						AttestationType: "none",
					},
				}
				mutate = func(ctx context.Context) error { return store.SavePersonalCredential(ctx, scope, key) }
			case "totp":
				box, err := sealed.New(bytes.Repeat([]byte{7}, 32), "identity.totp")
				if err != nil {
					t.Fatal(err)
				}

				ciphertext, err := box.Seal(scope.AccountID, []byte("12345678901234567890"))
				if err != nil {
					t.Fatal(err)
				}

				record := identity.TOTPRecord{
					ID:                uuid.NewString(),
					AccountID:         scope.AccountID,
					EnrollmentVersion: 1,
					Ciphertext:        ciphertext,
					CreatedAt:         *now,
					ExpiresAt:         now.Add(10 * time.Minute),
					LastStep:          -1,
				}

				if err := reader.SavePendingTOTP(t.Context(), scope, record); err != nil {
					t.Fatal(err)
				}

				mutate = func(ctx context.Context) error { return store.ConfirmTOTP(ctx, scope, record.ID, now.Unix()/30, *now) }
			case "recovery":
				if err := reader.SaveRecoveryCodes(
					t.Context(),
					scope,
					[]identity.RecoveryCode{{Hash: oldHash, CreatedAt: *now}},
				); err != nil {
					t.Fatal(err)
				}

				mutate = func(ctx context.Context) error {
					return store.SaveRecoveryCodes(
						ctx,
						scope,
						[]identity.RecoveryCode{
							{Hash: sha256.Sum256([]byte("new-private-code")), CreatedAt: *now},
						},
					)
				}
			}

			if _, err := pool.Exec(
				t.Context(),
				`ALTER TABLE notification_deliveries ADD CONSTRAINT test_security_notice_rejection CHECK(kind<>'security_notice')`,
			); err != nil {
				t.Fatal(err)
			}

			if err := mutate(t.Context()); !errors.Is(err, identity.ErrSecurityStateUnavailable) {
				t.Fatal("failed notice did not abort MFA change safely", err)
			}

			account, err := reader.Account(t.Context(), scope.AccountID)

			if err != nil || account.AuthVersion != 1 {
				t.Fatal("notice failure committed account epoch", err)
			}

			switch scenario {
			case "passkey":
				var count int

				if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM webauthn_credentials`).
					Scan(&count); err != nil ||
					count != 0 {
					t.Fatal("notice failure committed private credential", err)
				}
			case "totp":
				record, err := reader.TOTP(t.Context(), scope.AccountID)

				if err != nil || record.ConfirmedAt != nil || record.LastStep != -1 {
					t.Fatal("notice failure committed TOTP confirmation", err)
				}
			case "recovery":
				var unchanged bool

				if err := pool.QueryRow(t.Context(), `SELECT count(*)=1 AND bool_and(code_hash=$2) FROM recovery_codes WHERE account_id=$1`, scope.AccountID, oldHash[:]).
					Scan(&unchanged); err != nil ||
					!unchanged {
					t.Fatal("notice failure replaced recovery codes", err)
				}
			}

			if _, err := pool.Exec(
				t.Context(),
				`ALTER TABLE notification_deliveries DROP CONSTRAINT test_security_notice_rejection`,
			); err != nil {
				t.Fatal(err)
			}

			if err := mutate(t.Context()); err != nil {
				t.Fatal("aborted MFA update could not be retried", err)
			}
		})
	}
}

func TestPostgresDisabledOrUnverifiedMFAChangesDoNotQueueMail(t *testing.T) {
	for _, scenario := range []string{"disabled", "unverified"} {
		t.Run(scenario, func(t *testing.T) {
			_, _, pool, codec, owner, now := accountMailFixture(t)
			if scenario == "disabled" {
				codec = nil
			} else if _, err := pool.Exec(t.Context(), `UPDATE admin_accounts SET email_verified_at=NULL WHERE account_id=$1`, owner.AccountID); err != nil {
				t.Fatal(err)
			}

			store := transactionpg.NewIdentityWithNotifications(
				pool,
				codec,
				func() time.Time { return *now },
			)
			key := identity.NamedCredential{
				Name:      "First key",
				CreatedAt: *now,
				Credential: webauthn.Credential{
					ID:              []byte("first-key"),
					PublicKey:       []byte("public"),
					AttestationType: "none",
				},
			}

			if err := store.SavePersonalCredential(
				t.Context(),
				identity.AccountScope{
					AccountID:   owner.AccountID,
					AuthVersion: 1,
					Purpose:     identity.SessionAdmin,
				},
				key,
			); err != nil {
				t.Fatal(err)
			}

			var count int

			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries`).
				Scan(&count); err != nil ||
				count != 0 {
				t.Fatal("unconfigured/unverified address received email", err)
			}
		})
	}
}
