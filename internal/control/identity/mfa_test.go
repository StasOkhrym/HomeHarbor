package identity_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

func mfaFixture(
	t *testing.T,
) (*identity.MFAService, *memory.Repository, identity.Principal, *time.Time) {
	t.Helper()
	store := memory.NewRepository()

	now := time.Unix(59, 0).UTC()

	store.SetAccountForTest(
		identity.Account{
			ID:           "a",
			Email:        "a@example.test",
			Role:         identity.RoleAdmin,
			Status:       identity.AccountActive,
			AuthVersion:  3,
			PasswordHash: "private-hash",
			UserHandle:   []byte("account-a"),
		},
	)

	passkeys, err := identity.NewPasskeyService(
		identity.PasskeyConfig{
			RPID:          "home.example.test",
			RPOrigin:      "https://home.example.test",
			EncryptionKey: bytes.Repeat([]byte{7}, 32),
			CeremonyTTL:   time.Minute,
		},
		store,
		store,
		func() time.Time { return now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	recovery := identity.NewService(store, store, store, func() time.Time { return now }, nil)
	service, err := identity.NewMFAService(
		identity.MFAConfig{EncryptionKey: bytes.Repeat([]byte{7}, 32)},
		store,
		passkeys,
		recovery,
		func() time.Time { return now },
		bytes.NewReader([]byte(strings.Repeat("12345678901234567890", 20))),
	)
	if err != nil {
		t.Fatal(err)
	}

	principal := identity.Principal{
		AccountID:       "a",
		Role:            identity.RoleAdmin,
		Purpose:         identity.SessionAdmin,
		Method:          "recovery",
		AuthVersion:     3,
		AuthenticatedAt: now.Add(-time.Second),
	}

	return service, store, principal, &now
}

func TestTOTPEnrollmentNeedsRecentPersonalAuthority(t *testing.T) {
	service, store, principal, now := mfaFixture(t)
	for _, change := range []string{"anonymous", "migration", "stale-epoch", "old-mfa", "future-mfa"} {
		candidate := principal
		switch change {
		case "anonymous":
			candidate = identity.Principal{}
		case "migration":
			candidate.Purpose = identity.SessionMigration
		case "stale-epoch":
			candidate.AuthVersion = 2
		case "old-mfa":
			candidate.AuthenticatedAt = now.Add(-5 * time.Minute)
		case "future-mfa":
			candidate.AuthenticatedAt = now.Add(time.Second)
		}

		if _, err := service.BeginTOTP(t.Context(), candidate); err == nil {
			t.Fatalf("%s proof enrolled a factor", change)
		}
	}

	if _, err := store.TOTP(t.Context(), "a"); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("rejected authority persisted a seed", err)
	}
}

func TestTOTPEnrollmentEncryptsSeedAndLoginConsumesEachStepOnce(t *testing.T) {
	service, store, principal, now := mfaFixture(t)

	enrolled, err := service.BeginTOTP(t.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}

	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enrolled.Secret)

	if err != nil || string(seed) != "12345678901234567890" {
		t.Fatal("unexpected test seed", err)
	}

	stored, err := store.TOTP(t.Context(), "a")

	if err != nil || len(stored.Ciphertext) == 0 || bytes.Contains(stored.Ciphertext, seed) {
		t.Fatal("seed not protected at rest", err)
	}
	if !strings.HasPrefix(enrolled.URI, "otpauth://totp/") ||
		!strings.Contains(enrolled.URI, "period=30") ||
		enrolled.ExpiresAt.Sub(*now) != 10*time.Minute {
		t.Fatal("invalid enrollment metadata")
	}

	scope := identity.FactorContext{
		Binding: sha256.Sum256([]byte("verified-password-proof")),
		AccountScope: identity.AccountScope{
			AccountID:   "a",
			AuthVersion: 3,
			Purpose:     identity.SessionAdmin,
		},
	}

	if _, err := service.VerifySecondFactor(
		t.Context(),
		scope,
		identity.SecondFactorProof{Method: "totp", Code: "287082"},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("unconfirmed seed signed in", err)
	}

	if err := service.ConfirmTOTP(t.Context(), principal, "287082"); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), "a")

	if err != nil || account.AuthVersion != 4 {
		t.Fatal("factor activation did not invalidate old account epoch", err)
	}

	if _, err := service.BeginTOTP(
		t.Context(),
		principal,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale session changed MFA", err)
	}

	scope.AuthVersion = 4

	if _, err := service.VerifySecondFactor(
		t.Context(),
		scope,
		identity.SecondFactorProof{Method: "totp", Code: "287082"},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("confirmation code replayed for login", err)
	}

	*now = time.Unix(89, 0).UTC()

	method, err := service.VerifySecondFactor(
		t.Context(),
		scope,
		identity.SecondFactorProof{Method: "totp", Code: "359152"},
	)

	if err != nil || method != "totp" {
		t.Fatal("fresh TOTP not admitted", err)
	}

	if _, err := service.VerifySecondFactor(
		t.Context(),
		scope,
		identity.SecondFactorProof{Method: "totp", Code: "359152"},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("TOTP step signed in twice", err)
	}
}

func TestTOTPRemovalPreservesLastActiveFactor(t *testing.T) {
	service, _, principal, now := mfaFixture(t)

	if _, err := service.BeginTOTP(t.Context(), principal); err != nil {
		t.Fatal(err)
	}

	if err := service.ConfirmTOTP(t.Context(), principal, "287082"); err != nil {
		t.Fatal(err)
	}

	principal.AuthVersion = 4
	principal.AuthenticatedAt = *now

	if err := service.RemoveTOTP(t.Context(), principal); !errors.Is(err, identity.ErrLastMFA) {
		t.Fatalf("last active factor removed: %v", err)
	}
}

func TestTOTPConfirmationRejectsClockBeforeEnrollment(t *testing.T) {
	service, _, principal, now := mfaFixture(t)

	if _, err := service.BeginTOTP(t.Context(), principal); err != nil {
		t.Fatal(err)
	}

	*now = now.Add(-time.Second)

	if err := service.ConfirmTOTP(
		t.Context(),
		principal,
		"287082",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("confirmation preceded enrollment: %v", err)
	}
}
