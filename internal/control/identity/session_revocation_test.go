package identity_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestPersonalSessionRevocationNeedsRecentProofAndPreservesFactors(t *testing.T) {
	factors, store, principal, now := mfaFixture(t)

	if _, err := factors.BeginTOTP(t.Context(), principal); err != nil {
		t.Fatal(err)
	}

	if err := factors.ConfirmTOTP(t.Context(), principal, "287082"); err != nil {
		t.Fatal(err)
	}

	principal.AuthVersion++

	if codes, err := factors.RegenerateRecoveryCodes(
		t.Context(),
		principal,
	); err != nil ||
		len(codes) != 10 {
		t.Fatal("recovery fixture unavailable", err)
	}

	before, err := store.Account(t.Context(), principal.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	totp, err := store.TOTP(t.Context(), principal.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	sessions := identity.NewService(store, store, store, func() time.Time { return *now }, nil)
	request := identity.SessionRequest{
		AccountID:   principal.AccountID,
		AuthVersion: principal.AuthVersion,
		Purpose:     identity.SessionAdmin,
		Method:      "totp",
		TTL:         time.Hour,
	}
	tokens := make([]string, 0, 2)
	for range 2 {
		issued, err := sessions.CreateSession(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}

		tokens = append(tokens, issued.Token)
	}

	for _, change := range []func(*identity.Principal){
		func(p *identity.Principal) { p.AuthenticatedAt = now.Add(-5 * time.Minute) },
		func(p *identity.Principal) { p.AuthenticatedAt = now.Add(time.Second) },
		func(p *identity.Principal) { p.Purpose = identity.SessionMigration },
		func(p *identity.Principal) { p.Role = identity.RoleOwner },
		func(p *identity.Principal) { p.AuthVersion-- },
	} {
		invalid := principal

		change(&invalid)

		if err := factors.RevokeSessions(t.Context(), invalid); err == nil {
			t.Fatal("unverified scope revoked personal sessions")
		}
	}

	unchanged, err := store.Account(t.Context(), principal.AccountID)

	if err != nil || unchanged.AuthVersion != before.AuthVersion {
		t.Fatal("rejected scope changed authority", err)
	}

	if err := factors.RevokeSessions(t.Context(), principal); err != nil {
		t.Fatal(err)
	}

	after, err := store.Account(t.Context(), principal.AccountID)

	if err != nil || after.AuthVersion != before.AuthVersion+1 ||
		after.PasswordHash != before.PasswordHash ||
		after.Role != before.Role ||
		after.Status != before.Status ||
		!bytes.Equal(after.UserHandle, before.UserHandle) {
		t.Fatal("session revocation changed authentication methods/account", err)
	}

	afterTOTP, err := store.TOTP(t.Context(), principal.AccountID)

	if err != nil || !bytes.Equal(afterTOTP.Ciphertext, totp.Ciphertext) ||
		afterTOTP.LastStep != totp.LastStep ||
		afterTOTP.ConfirmedAt == nil ||
		!afterTOTP.ConfirmedAt.Equal(*totp.ConfirmedAt) {
		t.Fatal("session revocation changed authenticator", err)
	}

	for _, token := range tokens {
		if _, err := sessions.ValidateSession(
			t.Context(),
			token,
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatal("previous session survived account revocation", err)
		}
	}

	if _, err := sessions.CreateSession(
		t.Context(),
		request,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old password proof created a new session", err)
	}

	if err := factors.RevokeSessions(
		t.Context(),
		principal,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale caller repeated session revocation", err)
	}

	principal.AuthVersion = after.AuthVersion

	state, err := factors.Factors(t.Context(), principal)

	if err != nil || !state.TOTP || state.RecoveryCodesRemaining != 10 {
		t.Fatal("session revocation lost recovery/MFA", err)
	}

	request.AuthVersion = after.AuthVersion

	if _, err := sessions.CreateSession(t.Context(), request); err != nil {
		t.Fatal("fresh current proof cannot sign in after revocation", err)
	}
}
