package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestPostgresEmailTokensAreScopedSingleUseAndPreserveMFA(t *testing.T) {
	store, replica, pool, scope, record, now := totpSQLFixture(t, true)

	if err := store.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	if err := store.ConfirmTOTP(t.Context(), scope, record.ID, now.Unix()/30, now); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), scope.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion = account.AuthVersion

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET email_verified_at=$2 WHERE account_id=$1`,
		scope.AccountID,
		now,
	); err != nil {
		t.Fatal(err)
	}

	recovery := identity.RecoveryCode{
		Hash:      sha256.Sum256([]byte("retained-recovery")),
		CreatedAt: now,
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		scope,
		[]identity.RecoveryCode{recovery},
	); err != nil {
		t.Fatal(err)
	}

	token := identity.MailToken{
		Hash:        sha256.Sum256([]byte("opaque-reset")),
		AccountID:   account.ID,
		Email:       account.Email,
		AuthVersion: account.AuthVersion,
		Purpose:     identity.MailPasswordReset,
		CreatedAt:   now,
		ExpiresAt:   now.Add(15 * time.Minute),
	}

	if err := store.SaveMailToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	var committed atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			_, err := replica.ConsumeMailToken(
				t.Context(),
				identity.MailTokenUse{
					Hash:         token.Hash,
					Purpose:      identity.MailPasswordReset,
					Now:          now.Add(time.Second),
					PasswordHash: "replacement-private-hash",
				},
			)
			if err == nil {
				committed.Add(1)
			} else if !errors.Is(err, identity.ErrInvalidCredential) {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if committed.Load() != 1 {
		t.Fatal("reset redeemed more or less than once", committed.Load())
	}

	changed, err := store.Account(t.Context(), account.ID)

	if err != nil || changed.PasswordHash != "replacement-private-hash" ||
		changed.AuthVersion != account.AuthVersion+1 ||
		changed.Status != identity.AccountActive {
		t.Fatal("reset did not change only password authority", err)
	}

	var keys, codes int

	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM webauthn_credentials),(SELECT count(*) FROM recovery_codes WHERE used_at IS NULL)`).
		Scan(&keys, &codes); err != nil ||
		keys != 1 ||
		codes != 1 {
		t.Fatal("reset deleted MFA/recovery", err)
	}

	retained, err := store.TOTP(t.Context(), account.ID)

	if err != nil || retained.ConfirmedAt == nil ||
		!bytes.Equal(retained.Ciphertext, record.Ciphertext) {
		t.Fatal("reset changed TOTP", err)
	}
	if scope.Allows(changed) {
		t.Fatal("old account/session scope survived reset")
	}
}

func TestPostgresEmailTokensRejectExpiredFuturePurposeAndEpoch(t *testing.T) {
	for _, scenario := range []string{"expired", "future", "purpose", "epoch", "email", "unverified"} {
		t.Run(scenario, func(t *testing.T) {
			store, _, pool, scope, _, now := totpSQLFixture(t, false)

			if _, err := pool.Exec(
				t.Context(),
				`UPDATE admin_accounts SET email_verified_at=$2 WHERE account_id=$1`,
				scope.AccountID,
				now,
			); err != nil {
				t.Fatal(err)
			}

			account, err := store.Account(t.Context(), scope.AccountID)
			if err != nil {
				t.Fatal(err)
			}

			token := identity.MailToken{
				Hash:        sha256.Sum256([]byte(scenario)),
				AccountID:   account.ID,
				Email:       account.Email,
				AuthVersion: account.AuthVersion,
				Purpose:     identity.MailPasswordReset,
				CreatedAt:   now,
				ExpiresAt:   now.Add(15 * time.Minute),
			}

			if err := store.SaveMailToken(t.Context(), token); err != nil {
				t.Fatal(err)
			}

			use := identity.MailTokenUse{
				Hash:         token.Hash,
				Purpose:      token.Purpose,
				Now:          now.Add(time.Second),
				PasswordHash: "new-private-hash",
			}
			switch scenario {
			case "expired":
				use.Now = token.ExpiresAt
			case "future":
				use.Now = now.Add(-time.Second)
			case "purpose":
				use.Purpose = identity.MailEmailVerification
			case "epoch":
				_, err = pool.Exec(
					t.Context(),
					`UPDATE admin_accounts SET auth_version=auth_version+1 WHERE account_id=$1`,
					account.ID,
				)
			case "email":
				_, err = pool.Exec(
					t.Context(),
					`UPDATE admin_accounts SET email='changed@example.test' WHERE account_id=$1`,
					account.ID,
				)
			case "unverified":
				_, err = pool.Exec(
					t.Context(),
					`UPDATE admin_accounts SET email_verified_at=NULL WHERE account_id=$1`,
					account.ID,
				)
			}

			if err != nil {
				t.Fatal(err)
			}

			if _, err := store.ConsumeMailToken(
				t.Context(),
				use,
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatal("invalid token admitted", err)
			}

			unchanged, err := store.Account(t.Context(), account.ID)

			if err != nil || unchanged.PasswordHash != account.PasswordHash {
				t.Fatal("invalid token changed password", err)
			}
		})
	}
}

func TestPostgresMailTokenBoundTransactionCannotEscapeRollback(t *testing.T) {
	store, _, pool, scope, _, now := totpSQLFixture(t, false)

	account, err := store.Account(t.Context(), scope.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	token := identity.MailToken{
		Hash:        sha256.Sum256([]byte("verify-private")),
		AccountID:   account.ID,
		Email:       account.Email,
		AuthVersion: account.AuthVersion,
		Purpose:     identity.MailEmailVerification,
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	if err := Bind(tx).SaveMailToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeMailToken(
		t.Context(),
		identity.MailTokenUse{Hash: token.Hash, Purpose: token.Purpose, Now: now.Add(time.Second)},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("nested identity transaction escaped rollback", err)
	}
}

func TestPostgresEmailVerificationDoesNotCreateAdminAuthority(t *testing.T) {
	store, _, _, scope, _, now := totpSQLFixture(t, false)

	account, err := store.Account(t.Context(), scope.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	token := identity.MailToken{
		Hash:        sha256.Sum256([]byte("verify-private")),
		AccountID:   account.ID,
		Email:       account.Email,
		AuthVersion: account.AuthVersion,
		Purpose:     identity.MailEmailVerification,
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}

	if err := store.SaveMailToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	verified, err := store.ConsumeMailToken(
		t.Context(),
		identity.MailTokenUse{Hash: token.Hash, Purpose: token.Purpose, Now: now.Add(time.Second)},
	)

	if err != nil || verified.EmailVerifiedAt == nil ||
		verified.PasswordHash != account.PasswordHash ||
		verified.AuthVersion != account.AuthVersion ||
		verified.Status != account.Status {
		t.Fatal("email verification changed authentication authority", err)
	}

	if _, err := store.ConsumeMailToken(
		t.Context(),
		identity.MailTokenUse{
			Hash:    token.Hash,
			Purpose: token.Purpose,
			Now:     now.Add(2 * time.Second),
		},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("email proof reused", err)
	}
}

func TestPostgresInvitationRemainsUnprivilegedUntilMFA(t *testing.T) {
	store, replica, pool, ownerScope, _, now := totpSQLFixture(t, false)
	candidate := identity.Account{
		ID:          "invited-admin",
		Email:       "guest@example.test",
		Role:        identity.RoleAdmin,
		Status:      identity.AccountInvited,
		AuthVersion: 1,
		UserHandle:  []byte("independent-user-handle"),
		CreatedAt:   now,
	}

	if err := store.PrepareAdminInvitation(t.Context(), ownerScope, candidate); err != nil {
		t.Fatal(err)
	}

	token := identity.MailToken{
		Hash:        sha256.Sum256([]byte("private-invitation")),
		AccountID:   candidate.ID,
		Email:       candidate.Email,
		AuthVersion: 1,
		Purpose:     identity.MailAdminInvitation,
		CreatedAt:   now,
		ExpiresAt:   now.Add(24 * time.Hour),
	}

	if err := store.SaveMailToken(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	accepted, err := replica.ConsumeMailToken(
		t.Context(),
		identity.MailTokenUse{
			Hash:         token.Hash,
			Purpose:      token.Purpose,
			Now:          now.Add(time.Second),
			PasswordHash: "invited-password-hash",
		},
	)

	if err != nil || accepted.Status != identity.AccountInvited ||
		accepted.EmailVerifiedAt == nil ||
		accepted.PasswordHash == "" ||
		accepted.AuthVersion != 2 {
		t.Fatal("invitation was activated too early or acceptance lost", err)
	}

	if _, err := accepted.Principal(
		identity.Session{
			AccountID:   accepted.ID,
			AuthVersion: accepted.AuthVersion,
			Purpose:     identity.SessionAdmin,
			Method:      "totp",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Hour),
		},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("email possession created full authority", err)
	}

	if err := store.RevokeAdmin(
		t.Context(),
		ownerScope,
		identity.OwnerAccountID,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("owner revoked", err)
	}

	if err := store.RevokeAdmin(
		t.Context(),
		identity.AccountScope{
			AccountID:   candidate.ID,
			AuthVersion: 2,
			Purpose:     identity.SessionAdmin,
		},
		identity.OwnerAccountID,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("invited administrator gained account authority", err)
	}

	if err := store.RevokeAdmin(t.Context(), ownerScope, candidate.ID); err != nil {
		t.Fatal(err)
	}

	revoked, err := store.Account(t.Context(), candidate.ID)

	if err != nil || revoked.Status != identity.AccountRevoked || revoked.AuthVersion != 3 {
		t.Fatal("revocation not durable", err)
	}

	var tokens int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_mail_tokens WHERE account_id=$1`, candidate.ID).
		Scan(&tokens); err != nil ||
		tokens != 0 {
		t.Fatal("revoked account retains token", err)
	}
}
