package identity_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
)

func invitedEnrollmentFixture(
	t *testing.T,
) (*identity.EnrollmentService, *identity.LoginService, *identity.MFAService, *memory.Repository, *time.Time) {
	t.Helper()
	factors, store, _, now := mfaFixture(t)

	hasher, err := identity.NewPasswordHasher(2)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hasher.Hash(t.Context(), "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}

	account.Status = identity.AccountInvited
	account.PasswordHash = hash
	account.EmailVerifiedAt = now

	store.SetAccountForTest(account)
	proofs := memory.NewRepository()
	flow, err := identity.NewEnrollmentService(
		store,
		proofs,
		hasher,
		factors,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	normalProofs := memory.NewRepository()
	sessions := identity.NewService(
		store,
		normalProofs,
		store,
		func() time.Time { return *now },
		nil,
	)
	login, err := identity.NewLoginService(
		identity.LoginConfig{SessionTTL: time.Hour},
		store,
		normalProofs,
		sessions,
		hasher,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	return flow, login, factors, store, now
}

func TestInvitedTOTPEnrollmentRequiresPasswordAndFreshNormalLogin(t *testing.T) {
	flow, login, factors, store, now := invitedEnrollmentFixture(t)

	if _, err := login.Password(
		t.Context(),
		"a@example.test",
		"invited long password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("invited password created normal proof", err)
	}

	if _, err := flow.Password(
		t.Context(),
		"a@example.test",
		"wrong password",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("wrong password created setup proof", err)
	}

	issued, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	scope, err := flow.Context(t.Context(), issued.Token)

	if err != nil || scope.Purpose != identity.SessionEnrollment {
		t.Fatal("setup proof has wrong authority", err)
	}

	if _, err := login.SecondFactorContext(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup proof entered normal preauth namespace", err)
	}

	if err := store.SaveRecoveryCodes(
		t.Context(),
		scope.AccountScope,
		[]identity.RecoveryCode{{CreatedAt: *now}},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup proof replaced recovery codes", err)
	}

	if _, err := factors.VerifySecondFactor(
		t.Context(),
		scope,
		identity.SecondFactorProof{Method: "totp", Code: "287082"},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("setup scope used normal MFA verification", err)
	}

	enrollment, err := flow.BeginTOTP(t.Context(), issued.Token)

	if err != nil || enrollment.Secret == "" {
		t.Fatal("setup could not enroll authenticator", err)
	}

	if err := flow.ConfirmTOTP(t.Context(), issued.Token, "287082"); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), "a")

	if err != nil || account.Status != identity.AccountActive || account.AuthVersion != 4 {
		t.Fatal("first factor did not atomically activate account", err)
	}

	if _, err := flow.Context(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("old setup proof survived activation", err)
	}

	normal, err := login.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := login.Complete(
		t.Context(),
		normal.Token,
		identity.SecondFactorProof{Method: "totp", Code: "287082"},
		factors,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("confirmation code replayed as login", err)
	}

	*now = time.Unix(89, 0).UTC()

	if _, err := login.Complete(
		t.Context(),
		normal.Token,
		identity.SecondFactorProof{Method: "totp", Code: "359152"},
		factors,
	); err != nil {
		t.Fatal("fresh password and next TOTP could not sign in", err)
	}
}

func TestInvitedEnrollmentAttemptsAndExpiryAreBounded(t *testing.T) {
	flow, _, _, store, now := invitedEnrollmentFixture(t)

	issued, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := flow.BeginTOTP(t.Context(), issued.Token); err != nil {
		t.Fatal(err)
	}

	for range 5 {
		if err := flow.ConfirmTOTP(
			t.Context(),
			issued.Token,
			"invalid",
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatal("bad factor attempt not rejected", err)
		}
	}

	if err := flow.ConfirmTOTP(
		t.Context(),
		issued.Token,
		"287082",
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("sixth attempt admitted", err)
	}

	fresh, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	*now = fresh.ExpiresAt

	if _, err := flow.Context(
		t.Context(),
		fresh.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("expired enrollment proof admitted", err)
	}

	account, err := store.Account(t.Context(), "a")

	if err != nil || account.Status != identity.AccountInvited {
		t.Fatal("rejected enrollment activated account", err)
	}
}

func TestInvitedPasskeyCeremonyBindsExactEnrollmentProof(t *testing.T) {
	flow, _, _, store, _ := invitedEnrollmentFixture(t)

	first, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	second, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	device := authenticator.New(t, "home.example.test", "https://home.example.test")

	begin, err := flow.BeginPasskey(t.Context(), first.Token, "iPhone")
	if err != nil {
		t.Fatal(err)
	}

	if err := flow.FinishPasskey(
		t.Context(),
		second.Token,
		begin.CeremonyID,
		device.Registration(t, begin.Options),
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("another enrollment proof finished ceremony", err)
	}

	begin, err = flow.BeginPasskey(t.Context(), first.Token, "iPhone")
	if err != nil {
		t.Fatal(err)
	}

	if err := flow.FinishPasskey(
		t.Context(),
		first.Token,
		begin.CeremonyID,
		device.Registration(t, begin.Options),
	); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), "a")

	if err != nil || account.Status != identity.AccountActive || account.AuthVersion != 4 {
		t.Fatal("signed key did not activate invited account", err)
	}

	if _, err := flow.Context(
		t.Context(),
		second.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("competing password proof survived activation", err)
	}
}

func TestInvitedEnrollmentReadsLiveAccountAuthority(t *testing.T) {
	flow, _, _, store, _ := invitedEnrollmentFixture(t)

	issued, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	original, err := store.Account(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}

	for _, scenario := range []string{"unverified", "password-cleared", "active", "revoked", "stale-epoch"} {
		t.Run(scenario, func(t *testing.T) {
			account := original
			switch scenario {
			case "unverified":
				account.EmailVerifiedAt = nil
			case "password-cleared":
				account.PasswordHash = ""
			case "active":
				account.Status = identity.AccountActive
			case "revoked":
				account.Status = identity.AccountRevoked
			case "stale-epoch":
				account.AuthVersion++
			}

			store.SetAccountForTest(account)

			if _, err := flow.Context(
				t.Context(),
				issued.Token,
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatal("stale setup proof admitted changed authority", err)
			}
		})
	}
}

type unavailableEnrollmentCleanup struct{ identity.PreauthRepository }

func (unavailableEnrollmentCleanup) ConsumePreauth(
	context.Context,
	[32]byte,
	time.Time,
) (identity.Preauth, error) {
	return identity.Preauth{}, identity.ErrSecurityStateUnavailable
}

func TestInvitedEnrollmentCleanupFailureCannotResurrectProof(t *testing.T) {
	_, _, factors, store, now := invitedEnrollmentFixture(t)

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	proofStore := unavailableEnrollmentCleanup{PreauthRepository: memory.NewRepository()}
	flow, err := identity.NewEnrollmentService(
		store,
		proofStore,
		hasher,
		factors,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	issued, err := flow.Password(t.Context(), "a@example.test", "invited long password")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := flow.BeginTOTP(t.Context(), issued.Token); err != nil {
		t.Fatal(err)
	}

	if err := flow.ConfirmTOTP(t.Context(), issued.Token, "287082"); err != nil {
		t.Fatal("committed activation reported a failed proof cleanup as failed enrollment", err)
	}

	if _, err := flow.Context(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("retained setup proof survived SQL epoch fence", err)
	}
}
