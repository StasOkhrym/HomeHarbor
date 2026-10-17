package identity_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
)

func TestSoftwareAuthenticatorProvesLegacyOwnerCeremony(t *testing.T) {
	store := memory.NewRepository()

	service := newPasskeyTestService(t, store, time.Now)
	device := authenticator.New(t, "tunnel.example.com", "https://tunnel.example.com")

	registration, err := service.BeginBootstrap(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	created, err := service.FinishBootstrap(
		t.Context(),
		registration.CeremonyID,
		device.Registration(t, registration.Options),
	)
	if err != nil {
		t.Fatal("valid registration rejected", err)
	}

	login, err := service.BeginLogin(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	response := device.Assertion(t, login.Options)

	proved, err := service.FinishLogin(t.Context(), login.CeremonyID, response)

	if err != nil || proved.Authenticator.SignCount <= created.Authenticator.SignCount {
		t.Fatal("valid owner assertion rejected", err)
	}

	if _, err := service.FinishLogin(
		t.Context(),
		login.CeremonyID,
		response,
	); !errors.Is(
		err,
		identity.ErrInvalidCeremony,
	) {
		t.Fatal("signed assertion replayed", err)
	}
}

func TestLegacyOwnerPasskeyCompletesPasswordBoundFactor(t *testing.T) {
	store := memory.NewRepository()

	now := time.Now().UTC()

	passkeys := newPasskeyTestService(t, store, func() time.Time { return now })
	device := authenticator.New(t, "tunnel.example.com", "https://tunnel.example.com")

	begin, err := passkeys.BeginBootstrap(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := passkeys.FinishBootstrap(
		t.Context(),
		begin.CeremonyID,
		device.Registration(t, begin.Options),
	); err != nil {
		t.Fatal(err)
	}

	store.SetAccountForTest(
		identity.Account{
			ID:           identity.OwnerAccountID,
			Role:         identity.RoleOwner,
			Status:       identity.AccountActive,
			AuthVersion:  2,
			Email:        "owner@example.test",
			PasswordHash: "private-hash",
			UserHandle:   []byte("homeharbor-admin-v1"),
		},
	)
	recovery := identity.NewService(store, store, store, func() time.Time { return now }, nil)
	mfa, err := identity.NewMFAService(
		identity.MFAConfig{EncryptionKey: bytes.Repeat([]byte{7}, 32)},
		store,
		passkeys,
		recovery,
		func() time.Time { return now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := passkeys.BeginLogin(t.Context()); !errors.Is(err, identity.ErrInvalidCredential) {
		t.Fatal("configured owner retained standalone login", err)
	}

	login, sessions := personalPasskeyLogin(
		t,
		store,
		&now,
		identity.OwnerAccountID,
		2,
		"verified-owner-password",
	)

	context, err := login.SecondFactorContext(t.Context(), "verified-owner-password")
	if err != nil {
		t.Fatal(err)
	}

	assertion, err := mfa.BeginPasskeyLogin(t.Context(), context)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := login.Complete(
		t.Context(),
		"verified-owner-password",
		identity.SecondFactorProof{
			Method:     "passkey",
			CeremonyID: assertion.CeremonyID,
			Response:   device.Assertion(t, assertion.Options),
		},
		mfa,
	)
	if err != nil {
		t.Fatal("preserved owner key rejected in MFA", err)
	}

	principal, err := sessions.ValidateSession(t.Context(), issued.Token)

	if err != nil || principal.AccountID != identity.OwnerAccountID ||
		!principal.CanManageAccounts() {
		t.Fatalf("wrong migrated owner authority: %+v %v", principal, err)
	}
}
