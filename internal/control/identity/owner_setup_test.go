package identity_test

import (
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestOwnerPasswordSetupRequiresFreshMigrationAndKeepsPasskeys(t *testing.T) {
	login, store, sessions, now := preauthFixture(t)
	handle := []byte("homeharbor-admin-v1")

	if err := store.SaveBootstrapCredential(
		t.Context(),
		handle,
		webauthn.Credential{
			ID:              []byte("legacy-owner-key"),
			PublicKey:       []byte("public"),
			AttestationType: "none",
		},
	); err != nil {
		t.Fatal(err)
	}

	migration, err := sessions.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
			Method:    "passkey",
			TTL:       5 * time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := sessions.ValidateSession(t.Context(), migration.Token)
	if err != nil {
		t.Fatal(err)
	}

	for _, invalid := range []identity.Principal{
		{},
		{AccountID: "a", Role: identity.RoleAdmin, Purpose: identity.SessionAdmin, AuthVersion: 3, Method: "totp", AuthenticatedAt: *now},
		{AccountID: identity.OwnerAccountID, Role: identity.RoleOwner, Purpose: identity.SessionMigration, AuthVersion: 1, Method: "passkey", AuthenticatedAt: now.Add(-5 * time.Minute)},
	} {
		if err := login.ConfigureOwner(
			t.Context(),
			invalid,
			"owner@example.test",
			"new private password",
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("invalid setup authority admitted: %v", err)
		}
	}

	if err := login.ConfigureOwner(
		t.Context(),
		principal,
		" Owner@EXAMPLE.TEST ",
		"new private password",
	); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), identity.OwnerAccountID)

	if err != nil || account.Email != "owner@example.test" ||
		account.Status != identity.AccountActive ||
		account.AuthVersion != 2 {
		t.Fatalf("wrong owner activation: %+v %v", account, err)
	}

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	if err := hasher.Verify(t.Context(), account.PasswordHash, "new private password"); err != nil {
		t.Fatal("password not stored as verified hash", err)
	}

	keys, err := store.Credentials(t.Context(), handle)

	if err != nil || len(keys) != 1 || string(keys[0].ID) != "legacy-owner-key" {
		t.Fatal("owner password setup replaced legacy passkey", err)
	}

	if _, err := sessions.ValidateSession(
		t.Context(),
		migration.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old migration session survived activation")
	}

	if err := login.ConfigureOwner(
		t.Context(),
		principal,
		"attacker@example.test",
		"another private password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup proof replayed", err)
	}
}
