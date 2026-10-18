package transactions_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	notificationpg "github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
	transactionpg "github.com/StasOkhrym/homeharbor/internal/control/transactions"
	"github.com/StasOkhrym/homeharbor/internal/platform/sealed"
)

func TestPostgresSessionRevocationQueuesNoticeAtomicallyAndCancelsOldLinks(t *testing.T) {
	flow, reader, pool, codec, owner, now := accountMailFixture(t)
	scope := identity.AccountScope{
		AccountID:   owner.AccountID,
		AuthVersion: 1,
		Purpose:     identity.SessionAdmin,
	}
	key := identity.NamedCredential{
		Name:      "Preserved key",
		CreatedAt: *now,
		Credential: webauthn.Credential{
			ID:              []byte("session-key"),
			PublicKey:       []byte("fixture-public-key"),
			AttestationType: "none",
		},
	}

	if err := reader.SavePersonalCredential(t.Context(), scope, key); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++

	box, err := sealed.New(bytes.Repeat([]byte{7}, 32), "identity.totp")
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := box.Seal(owner.AccountID, []byte("12345678901234567890"))
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

	if err := reader.SavePendingTOTP(t.Context(), scope, record); err != nil {
		t.Fatal(err)
	}

	if err := reader.ConfirmTOTP(t.Context(), scope, record.ID, now.Unix()/30, *now); err != nil {
		t.Fatal(err)
	}

	scope.AuthVersion++
	owner.AuthVersion = scope.AuthVersion
	store := transactionpg.NewIdentityWithNotifications(
		pool,
		codec,
		func() time.Time { return *now },
	)
	codes := []identity.RecoveryCode{
		{Hash: sha256.Sum256([]byte("PRIVATE_RECOVERY_CODE")), CreatedAt: *now},
	}

	if err := store.SaveRecoveryCodes(t.Context(), scope, codes); err != nil {
		t.Fatal(err)
	}

	if err := flow.RequestPasswordReset(t.Context(), owner.Email); err != nil {
		t.Fatal(err)
	}

	resetToken := queuedAccountToken(t, pool, codec, notifications.PasswordReset, *now)
	queue := notificationpg.New(pool)
	// Only reset and an older security notice exist. Claim until the reset is
	// leased; the notice remains pending and must never be cancelled by logout.
	var reset notifications.Delivery
	for range 2 {
		claimed, ok, err := queue.Claim(t.Context())

		if err != nil || !ok {
			t.Fatal("owned reset fixture not claimable", err)
		}

		if claimed.Kind == notifications.PasswordReset {
			reset = claimed
			break
		}
	}

	if reset.ID == "" {
		t.Fatal("reset lease unavailable")
	}

	other, err := flow.InviteAdmin(t.Context(), owner, "unrelated@example.test")
	if err != nil {
		t.Fatal(err)
	}

	before, err := reader.Account(t.Context(), owner.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	beforeTOTP, err := reader.TOTP(t.Context(), owner.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	beforeFactors, err := reader.FactorState(t.Context(), scope)

	if err != nil || !beforeFactors.TOTP || len(beforeFactors.Passkeys) != 1 ||
		beforeFactors.RecoveryCodesRemaining != 1 {
		t.Fatal("preserved-factor fixture invalid", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries ADD CONSTRAINT reject_new_session_notice CHECK (kind <> 'security_notice') NOT VALID`,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeSessions(
		t.Context(),
		scope,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatal("revocation committed without its required durable notice", err)
	}

	unchanged, err := reader.Account(t.Context(), owner.AccountID)

	if err != nil || unchanged.AuthVersion != before.AuthVersion {
		t.Fatal("queue failure invalidated sessions", err)
	}

	var tokenCount int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_mail_tokens WHERE account_id=$1`, owner.AccountID).
		Scan(&tokenCount); err != nil ||
		tokenCount != 1 {
		t.Fatal("failed revocation deleted mail proof", err)
	}

	var status string

	if err := pool.QueryRow(t.Context(), `SELECT status FROM notification_deliveries WHERE id=$1`, reset.ID).
		Scan(&status); err != nil ||
		status != "pending" {
		t.Fatal("failed revocation cancelled old link", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries DROP CONSTRAINT reject_new_session_notice`,
	); err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeSessions(t.Context(), scope); err != nil {
		t.Fatal("repaired revocation failed", err)
	}

	after, err := reader.Account(t.Context(), owner.AccountID)

	if err != nil || after.AuthVersion != before.AuthVersion+1 || after.Status != before.Status ||
		after.PasswordHash != before.PasswordHash ||
		!bytes.Equal(after.UserHandle, before.UserHandle) {
		t.Fatal("revocation changed account credentials", err)
	}

	current := scope
	current.AuthVersion = after.AuthVersion

	state, err := reader.FactorState(t.Context(), current)

	if err != nil || !state.TOTP || len(state.Passkeys) != 1 || state.RecoveryCodesRemaining != 1 {
		t.Fatal("revocation lost factors/recovery", err)
	}

	afterTOTP, err := reader.TOTP(t.Context(), owner.AccountID)

	if err != nil || !bytes.Equal(afterTOTP.Ciphertext, beforeTOTP.Ciphertext) ||
		afterTOTP.LastStep != beforeTOTP.LastStep {
		t.Fatal("revocation changed authenticator state", err)
	}

	credential, err := reader.Credential(t.Context(), after.UserHandle, key.Credential.ID)

	if err != nil || !bytes.Equal(credential.PublicKey, []byte("fixture-public-key")) {
		t.Fatal("revocation changed passkey", err)
	}

	if err := reader.ConsumeRecoveryCode(
		t.Context(),
		identity.RecoveryUse{Scope: current, Hash: codes[0].Hash, UsedAt: *now},
	); err != nil {
		t.Fatal("original recovery code not preserved", err)
	}

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_mail_tokens WHERE account_id=$1`, owner.AccountID).
		Scan(&tokenCount); err != nil ||
		tokenCount != 0 {
		t.Fatal("old mail proofs survived session revocation", err)
	}

	var cancelled int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE id=$1 AND status='cancelled' AND private_payload IS NULL`, reset.ID).
		Scan(&cancelled); err != nil ||
		cancelled != 1 {
		t.Fatal("obsolete reset payload not scrubbed", err)
	}

	if err := queue.Finish(
		t.Context(),
		reset,
		notifications.DeliverySent,
	); !errors.Is(
		err,
		notifications.ErrLeaseLost,
	) {
		t.Fatal("old reset delivery lease survived cancellation", err)
	}

	if _, err := flow.ResetPassword(
		t.Context(),
		resetToken,
		"new long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old reset link changed password after logout-all", err)
	}

	var notices, otherPending int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE account_id=$1 AND kind='security_notice' AND status='pending'`, owner.AccountID).
		Scan(&notices); err != nil ||
		notices != 2 {
		t.Fatal("security notices cancelled or absent", err)
	}

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE account_id=$1 AND kind='admin_invitation' AND status='pending'`, other.ID).
		Scan(&otherPending); err != nil ||
		otherPending != 1 {
		t.Fatal("another account's invitation cancelled", err)
	}
}
