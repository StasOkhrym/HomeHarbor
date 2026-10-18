package transactions_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identitypg "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	transactionpg "github.com/StasOkhrym/homeharbor/internal/control/transactions"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func accountMailFixture(
	t *testing.T,
) (*workflows.AccountMail, *identitypg.Repository, *pgxpool.Pool, *notifications.Codec, identity.Principal, *time.Time) {
	t.Helper()
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)

	hasher, err := identity.NewPasswordHasher(2)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hasher.Hash(t.Context(), "original long owner password")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET email='owner@example.test',password_hash=$1,status='active',email_verified_at=$2 WHERE account_id=$3`,
		hash,
		now,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	codec, err := notifications.NewCodec(
		bytes.Repeat([]byte{7}, 32),
		"https://control.example.test",
	)
	if err != nil {
		t.Fatal(err)
	}

	store := identitypg.New(pool)
	flow, err := workflows.NewAccountMail(
		transactionpg.NewAccountMailUnitOfWork(pool),
		store,
		hasher,
		codec,
		func() time.Time { return now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	owner := identity.Principal{
		AccountID:       identity.OwnerAccountID,
		Email:           "owner@example.test",
		Role:            identity.RoleOwner,
		Purpose:         identity.SessionAdmin,
		Method:          "totp",
		AuthVersion:     1,
		AuthenticatedAt: now,
	}

	return flow, store, pool, codec, owner, &now
}

func queuedAccountToken(
	t *testing.T,
	pool *pgxpool.Pool,
	codec *notifications.Codec,
	kind notifications.Kind,
	now time.Time,
) string {
	t.Helper()
	var prepared notifications.Prepared
	var fingerprint []byte

	if err := pool.QueryRow(t.Context(), `SELECT id::text,account_id,kind,private_payload,logical_fingerprint,created_at,expires_at FROM notification_deliveries WHERE kind=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1`, kind).
		Scan(&prepared.ID, &prepared.AccountID, &prepared.Kind, &prepared.Ciphertext, &fingerprint, &prepared.CreatedAt, &prepared.ExpiresAt); err != nil {
		t.Fatal(err)
	}

	copy(prepared.Fingerprint[:], fingerprint)

	message, err := codec.Render(prepared, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range strings.Split(message.Text, "\n") {
		if strings.HasPrefix(line, "https://") {
			link, err := url.Parse(line)
			if err != nil {
				t.Fatal(err)
			}

			fragment, err := url.ParseQuery(link.Fragment)
			if err != nil {
				t.Fatal(err)
			}

			if token := fragment.Get("token"); token != "" {
				return token
			}
		}
	}

	t.Fatal("queued mail has no private token link")

	return ""
}

func TestPostgresAccountMailResetIsPrivateAtomicAndGeneric(t *testing.T) {
	flow, store, pool, codec, owner, now := accountMailFixture(t)

	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO admin_accounts(account_id,email,role,status,password_hash,user_handle)VALUES('unverified','unverified@example.test','admin','active','hash','unverified')`,
	); err != nil {
		t.Fatal(err)
	}

	for _, address := range []string{owner.Email, "missing@example.test", "unverified@example.test", "invalid address", owner.Email} {
		if err := flow.RequestPasswordReset(t.Context(), address); err != nil {
			t.Fatal("reset request exposed account existence or duplicate state", err)
		}
	}

	var count int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries`).
		Scan(&count); err != nil ||
		count != 1 {
		t.Fatal("unknown/unverified/duplicate reset queued extra mail", err)
	}

	token := queuedAccountToken(t, pool, codec, notifications.PasswordReset, *now)

	hash := sha256.Sum256([]byte(token))
	var private bool

	if err := pool.QueryRow(t.Context(), `SELECT token_hash=$1 FROM admin_mail_tokens WHERE account_id=$2`, hash[:], owner.AccountID).
		Scan(&private); err != nil ||
		!private {
		t.Fatal("reset token hash differs", err)
	}

	resetSubject, err := flow.ResetPassword(t.Context(), token, "replacement long password")

	if err != nil || resetSubject.ID != owner.AccountID || resetSubject.Email != owner.Email {
		t.Fatal("reset lost its committed safe account subject", err)
	}

	if _, err := flow.ResetPassword(
		t.Context(),
		token,
		"another long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("reset replay admitted", err)
	}

	account, err := store.Account(t.Context(), owner.AccountID)

	if err != nil || account.AuthVersion != 2 || account.Status != identity.AccountActive {
		t.Fatal("reset account authority incorrect", err)
	}

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	if err := hasher.Verify(
		t.Context(),
		account.PasswordHash,
		"replacement long password",
	); err != nil {
		t.Fatal("new password not stored", err)
	}

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE kind='security_notice' AND status='pending'`).
		Scan(&count); err != nil ||
		count != 1 {
		t.Fatal("reset security notice not atomically queued", err)
	}
}

func TestPostgresAccountMailRollsTokenBackWhenQueueRejects(t *testing.T) {
	flow, _, pool, _, owner, _ := accountMailFixture(t)

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries ADD CONSTRAINT test_mail_rejection CHECK(kind<>'password_reset')`,
	); err != nil {
		t.Fatal(err)
	}

	if err := flow.RequestPasswordReset(
		t.Context(),
		owner.Email,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatal("queue rejection was hidden or leaked a raw SQL diagnostic", err)
	}

	var count int

	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM admin_mail_tokens)+(SELECT count(*) FROM notification_deliveries)`).
		Scan(&count); err != nil ||
		count != 0 {
		t.Fatal("failed mail enqueue left redeemable token", err)
	}
}

func TestPostgresAccountInvitationRequiresRecentOwnerAndVerifiesWithoutActivation(t *testing.T) {
	flow, store, pool, codec, owner, now := accountMailFixture(t)
	stale := owner
	stale.AuthenticatedAt = now.Add(-5 * time.Minute)

	if _, err := flow.InviteAdmin(
		t.Context(),
		stale,
		"guest@example.test",
	); !errors.Is(
		err,
		identity.ErrRecentAuthentication,
	) {
		t.Fatal("stale owner invited administrator", err)
	}

	forged := owner
	forged.Role = identity.RoleAdmin

	if _, err := flow.InviteAdmin(
		t.Context(),
		forged,
		"guest@example.test",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("non-owner invited administrator", err)
	}

	if _, err := flow.InviteAdmin(t.Context(), owner, "Guest@Example.Test"); err != nil {
		t.Fatal(err)
	}

	token := queuedAccountToken(t, pool, codec, notifications.AdminInvitation, *now)

	if _, err := flow.InviteAdmin(
		t.Context(),
		owner,
		"guest@example.test",
	); !errors.Is(
		err,
		identity.ErrMailRateLimited,
	) {
		t.Fatal("repeated invitation bypassed account mail quota", err)
	}

	unchanged, err := store.AccountByEmail(t.Context(), "guest@example.test")

	if err != nil || unchanged.AuthVersion != 1 {
		t.Fatal("rate-limited invitation committed an epoch change", err)
	}

	*now = now.Add(61 * time.Second)

	if _, err := flow.InviteAdmin(t.Context(), owner, "guest@example.test"); err != nil {
		t.Fatal("expired delivery could not be reissued", err)
	}

	if _, err := flow.AcceptInvitation(
		t.Context(),
		token,
		"invited long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("superseded invitation survived reissue", err)
	}

	token = queuedAccountToken(t, pool, codec, notifications.AdminInvitation, *now)

	acceptedSubject, err := flow.AcceptInvitation(t.Context(), token, "invited long password")

	if err != nil || acceptedSubject.Email != "guest@example.test" || acceptedSubject.ID == "" {
		t.Fatal("accepted invitation lost its verified recipient", err)
	}

	account, err := store.AccountByEmail(t.Context(), "guest@example.test")

	if err != nil || account.ID != acceptedSubject.ID ||
		account.Status != identity.AccountInvited ||
		account.EmailVerifiedAt == nil ||
		account.AuthVersion != 3 {
		t.Fatal("invited administrator activated before MFA", err)
	}

	if _, err := flow.AcceptInvitation(
		t.Context(),
		token,
		"another long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("invitation replay accepted", err)
	}

	if _, err := flow.RevokeAdmin(
		t.Context(),
		owner,
		identity.OwnerAccountID,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("owner revoked", err)
	}

	if _, err := flow.RevokeAdmin(t.Context(), owner, account.ID); err != nil {
		t.Fatal(err)
	}

	revoked, err := store.Account(t.Context(), account.ID)

	if err != nil || revoked.Status != identity.AccountRevoked {
		t.Fatal("revocation failed", err)
	}
}

func TestPostgresAccountMailVerificationUsesPurposeWithoutSession(t *testing.T) {
	flow, store, pool, codec, owner, now := accountMailFixture(t)

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET email_verified_at=NULL WHERE account_id=$1`,
		owner.AccountID,
	); err != nil {
		t.Fatal(err)
	}

	if err := flow.RequestEmailVerification(t.Context(), owner); err != nil {
		t.Fatal(err)
	}

	token := queuedAccountToken(t, pool, codec, notifications.EmailVerification, *now)

	if _, err := flow.ResetPassword(
		t.Context(),
		token,
		"replacement long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("verification token reset password", err)
	}

	if _, err := flow.VerifyEmail(t.Context(), token); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), owner.AccountID)

	if err != nil || account.EmailVerifiedAt == nil || account.AuthVersion != 1 {
		t.Fatal("email proof changed authority", err)
	}
}

func TestPostgresAccountMailResetRollsBackWhenNoticeQueueRejects(t *testing.T) {
	flow, store, pool, codec, owner, now := accountMailFixture(t)

	if err := flow.RequestPasswordReset(t.Context(), owner.Email); err != nil {
		t.Fatal(err)
	}

	token := queuedAccountToken(t, pool, codec, notifications.PasswordReset, *now)

	before, err := store.Account(t.Context(), owner.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries ADD CONSTRAINT test_notice_rejection CHECK(kind<>'security_notice')`,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := flow.ResetPassword(
		t.Context(),
		token,
		"replacement long password",
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatal("notice failure did not abort reset", err)
	}

	after, err := store.Account(t.Context(), owner.AccountID)

	if err != nil || after.PasswordHash != before.PasswordHash ||
		after.AuthVersion != before.AuthVersion {
		t.Fatal("password changed despite failed atomic notice", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries DROP CONSTRAINT test_notice_rejection`,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := flow.ResetPassword(t.Context(), token, "replacement long password"); err != nil {
		t.Fatal("aborted reset burned the one-use token", err)
	}
}
