package identity_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

func TestPersonalSessionChecksLiveAccountAcrossInstances(t *testing.T) {
	for _, change := range []string{"revocation", "auth-version"} {
		t.Run(change, func(t *testing.T) {
			store := memory.NewRepository()

			now := time.Now().UTC()
			account := identity.Account{
				ID:           "admin-a",
				Role:         identity.RoleAdmin,
				Status:       identity.AccountActive,
				Email:        "a@example.test",
				PasswordHash: "hash",
				AuthVersion:  3,
			}

			store.SetAccountForTest(account)
			first := identity.NewService(store, store, store, func() time.Time { return now }, nil)
			second := identity.NewService(store, store, store, func() time.Time { return now }, nil)

			issued, err := first.CreateSession(
				t.Context(),
				identity.SessionRequest{
					AccountID:   account.ID,
					AuthVersion: account.AuthVersion,
					Purpose:     identity.SessionAdmin,
					Method:      "passkey",
					TTL:         time.Hour,
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			principal, err := second.ValidateSession(t.Context(), issued.Token)

			if err != nil || principal.AccountID != account.ID || !principal.CanManageNetwork() ||
				principal.CanManageAccounts() {
				t.Fatalf("wrong personal authority: %+v %v", principal, err)
			}

			if change == "revocation" {
				account.Status = identity.AccountRevoked
			} else {
				account.AuthVersion++
			}

			store.SetAccountForTest(account)

			if _, err := second.ValidateSession(
				t.Context(),
				issued.Token,
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatalf("stale session stayed authorized after %s: %v", change, err)
			}
		})
	}
}

func TestLegacyOwnerProofCreatesOnlyBoundedMigrationSession(t *testing.T) {
	store := memory.NewRepository()

	now := time.Now().UTC()
	account := identity.Account{
		ID:          identity.OwnerAccountID,
		Role:        identity.RoleOwner,
		Status:      identity.AccountSetup,
		AuthVersion: 1,
	}

	store.SetAccountForTest(account)
	service := identity.NewService(store, store, store, func() time.Time { return now }, nil)

	if _, err := service.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID:   account.ID,
			AuthVersion: account.AuthVersion,
			Purpose:     identity.SessionAdmin,
			Method:      "passkey",
			TTL:         time.Hour,
		},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("legacy proof promoted setup owner to administrator")
	}

	issued, err := service.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID: account.ID,
			Purpose:   identity.SessionMigration,
			Method:    "passkey",
			TTL:       time.Hour,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	principal, err := service.ValidateSession(t.Context(), issued.Token)

	if err != nil || principal.CanManageNetwork() || principal.CanManageAccounts() ||
		issued.ExpiresAt.Sub(now) > 5*time.Minute {
		t.Fatalf("migration session not restricted: %+v %v", principal, err)
	}
}

type unavailableAccounts struct{}

func (unavailableAccounts) Account(context.Context, string) (identity.Account, error) {
	return identity.Account{}, errors.New("private SQL diagnostic")
}

func TestPersonalSessionRejectsOldGlobalPayloadAndUnavailableAuthority(t *testing.T) {
	store := memory.NewRepository()

	now := time.Now().UTC()
	legacy := "legacy-global-token"

	if err := store.SaveSession(
		t.Context(),
		identity.Session{
			Hash:      sha256.Sum256([]byte(legacy)),
			CreatedAt: now,
			ExpiresAt: now.Add(time.Hour),
		},
	); err != nil {
		t.Fatal(err)
	}

	service := identity.NewService(
		store,
		store,
		unavailableAccounts{},
		func() time.Time { return now },
		nil,
	)

	if _, err := service.ValidateSession(
		t.Context(),
		legacy,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatalf("global payload acquired account authority: %v", err)
	}

	personal := "personal-token"

	if err := store.SaveSession(
		t.Context(),
		identity.Session{
			Hash:        sha256.Sum256([]byte(personal)),
			AccountID:   "a",
			AuthVersion: 1,
			Purpose:     identity.SessionAdmin,
			Method:      "passkey",
			CreatedAt:   now,
			ExpiresAt:   now.Add(time.Hour),
		},
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.ValidateSession(
		t.Context(),
		personal,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatalf("unavailable account authority did not fail closed: %v", err)
	}
}

func TestRecoveryCodesAreScopedAndRotationKeepsOtherAccounts(t *testing.T) {
	store := memory.NewRepository()
	for _, id := range []string{"a", "b"} {
		store.SetAccountForTest(
			identity.Account{
				ID:           id,
				Role:         identity.RoleAdmin,
				Status:       identity.AccountActive,
				Email:        id + "@example.test",
				PasswordHash: "hash",
				AuthVersion:  1,
			},
		)
	}

	service := identity.NewService(store, store, store, time.Now, nil)

	left, err := service.GenerateRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: "a", AuthVersion: 1, Purpose: identity.SessionAdmin},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}

	right, err := service.GenerateRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: "b", AuthVersion: 1, Purpose: identity.SessionAdmin},
		2,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.ConsumeRecoveryCode(
		t.Context(),
		identity.AccountScope{AccountID: "b", AuthVersion: 1, Purpose: identity.SessionAdmin},
		left[0],
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("another account consumed recovery code")
	}

	if err := service.ConsumeRecoveryCode(
		t.Context(),
		identity.AccountScope{AccountID: "a", AuthVersion: 1, Purpose: identity.SessionAdmin},
		left[0],
	); err != nil {
		t.Fatal(err)
	}

	if _, err := service.GenerateRecoveryCodes(
		t.Context(),
		identity.AccountScope{AccountID: "a", AuthVersion: 1, Purpose: identity.SessionAdmin},
		2,
	); err != nil {
		t.Fatal(err)
	}

	if err := service.ConsumeRecoveryCode(
		t.Context(),
		identity.AccountScope{AccountID: "a", AuthVersion: 1, Purpose: identity.SessionAdmin},
		left[1],
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("rotation retained old code")
	}

	if err := service.ConsumeRecoveryCode(
		t.Context(),
		identity.AccountScope{AccountID: "b", AuthVersion: 1, Purpose: identity.SessionAdmin},
		right[0],
	); err != nil {
		t.Fatal("rotation deleted another account's codes")
	}
}

func TestSessionCreationRequiresCurrentPasswordProofVersion(t *testing.T) {
	store := memory.NewRepository()

	store.SetAccountForTest(
		identity.Account{
			ID:           "a",
			Role:         identity.RoleAdmin,
			Status:       identity.AccountActive,
			AuthVersion:  3,
			Email:        "a@example.test",
			PasswordHash: "hash",
		},
	)
	service := identity.NewService(store, store, store, time.Now, nil)
	for _, version := range []uint64{0, 2} {
		if _, err := service.CreateSession(
			t.Context(),
			identity.SessionRequest{
				AccountID:   "a",
				AuthVersion: version,
				Purpose:     identity.SessionAdmin,
				Method:      "passkey",
				TTL:         time.Hour,
			},
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("stale/missing proof version %d created session: %v", version, err)
		}
	}
}
