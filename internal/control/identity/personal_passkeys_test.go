package identity_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
)

func enrollPersonalPasskey(
	t *testing.T,
	service *identity.MFAService,
	store *memory.Repository,
	principal identity.Principal,
) (*authenticator.Authenticator, identity.Principal) {
	t.Helper()
	device := authenticator.New(t, "home.example.test", "https://home.example.test")

	begin, err := service.BeginPasskeyEnrollment(t.Context(), principal, "MacBook")
	if err != nil {
		t.Fatal(err)
	}

	if err := service.FinishPasskeyEnrollment(
		t.Context(),
		principal,
		begin.CeremonyID,
		device.Registration(t, begin.Options),
	); err != nil {
		t.Fatal(err)
	}

	account, err := store.Account(t.Context(), principal.AccountID)
	if err != nil {
		t.Fatal(err)
	}

	principal.AuthVersion = account.AuthVersion

	return device, principal
}

func personalPasskeyLogin(
	t *testing.T,
	store *memory.Repository,
	now *time.Time,
	account string,
	version uint64,
	token string,
) (*identity.LoginService, *identity.Service) {
	t.Helper()

	if err := store.SavePreauth(
		t.Context(),
		identity.Preauth{
			Hash:        sha256.Sum256([]byte(token)),
			AccountID:   account,
			AuthVersion: version,
			CreatedAt:   *now,
			ExpiresAt:   now.Add(5 * time.Minute),
		},
	); err != nil {
		t.Fatal(err)
	}

	sessions := identity.NewService(store, store, store, func() time.Time { return *now }, nil)

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	login, err := identity.NewLoginService(
		identity.LoginConfig{SessionTTL: time.Hour},
		store,
		store,
		sessions,
		hasher,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	return login, sessions
}

func TestPersonalPasskeyEnrollmentAndPasswordProofBinding(t *testing.T) {
	service, store, principal, now := mfaFixture(t)

	device, principal := enrollPersonalPasskey(t, service, store, principal)

	state, err := service.Factors(t.Context(), principal)

	if err != nil || len(state.Passkeys) != 1 || state.Passkeys[0].Name != "MacBook" ||
		state.Passkeys[0].ID != base64.RawURLEncoding.EncodeToString(device.CredentialID) {
		t.Fatalf("personal passkey metadata missing: %+v %v", state, err)
	}
	if string(device.UserHandle) != "account-a" {
		t.Fatal("registration changed the stable personal account handle")
	}

	login, sessions := personalPasskeyLogin(
		t,
		store,
		now,
		"a",
		principal.AuthVersion,
		"correct-password-proof",
	)

	_, _ = personalPasskeyLogin(t, store, now, "a", principal.AuthVersion, "other-password-proof")

	store.SetAccountForTest(
		identity.Account{
			ID:           "b",
			Email:        "b@example.test",
			Role:         identity.RoleAdmin,
			Status:       identity.AccountActive,
			AuthVersion:  1,
			PasswordHash: "hash",
			UserHandle:   []byte("account-b"),
		},
	)
	_, _ = personalPasskeyLogin(t, store, now, "b", 1, "foreign-password-proof")
	for _, wrongToken := range []string{"other-password-proof", "foreign-password-proof"} {
		factor, err := login.SecondFactorContext(t.Context(), "correct-password-proof")
		if err != nil {
			t.Fatal(err)
		}

		begin, err := service.BeginPasskeyLogin(t.Context(), factor)
		if err != nil {
			t.Fatal(err)
		}

		proof := identity.SecondFactorProof{
			Method:     "passkey",
			CeremonyID: begin.CeremonyID,
			Response:   device.Assertion(t, begin.Options),
		}

		if _, err := login.Complete(
			t.Context(),
			wrongToken,
			proof,
			service,
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("assertion crossed password proof %s: %v", wrongToken, err)
		}
	}

	factor, err := login.SecondFactorContext(t.Context(), "correct-password-proof")
	if err != nil {
		t.Fatal(err)
	}

	begin, err := service.BeginPasskeyLogin(t.Context(), factor)
	if err != nil {
		t.Fatal(err)
	}

	proof := identity.SecondFactorProof{
		Method:     "passkey",
		CeremonyID: begin.CeremonyID,
		Response:   device.Assertion(t, begin.Options),
	}

	issued, err := login.Complete(t.Context(), "correct-password-proof", proof, service)
	if err != nil {
		t.Fatal(err)
	}

	current, err := sessions.ValidateSession(t.Context(), issued.Token)

	if err != nil || current.AccountID != "a" || current.Method != "passkey" ||
		!current.CanManageNetwork() {
		t.Fatalf("valid MFA did not issue scoped session: %+v %v", current, err)
	}

	if _, err := login.Complete(
		t.Context(),
		"correct-password-proof",
		proof,
		service,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("password/passkey proof replayed", err)
	}
}

func TestPersonalPasskeyRequiresUserVerification(t *testing.T) {
	service, store, principal, now := mfaFixture(t)

	device, principal := enrollPersonalPasskey(t, service, store, principal)

	login, _ := personalPasskeyLogin(t, store, now, "a", principal.AuthVersion, "password-proof")

	factor, err := login.SecondFactorContext(t.Context(), "password-proof")
	if err != nil {
		t.Fatal(err)
	}

	begin, err := service.BeginPasskeyLogin(t.Context(), factor)
	if err != nil {
		t.Fatal(err)
	}

	device.UserVerified = false

	if _, err := login.Complete(
		t.Context(),
		"password-proof",
		identity.SecondFactorProof{
			Method:     "passkey",
			CeremonyID: begin.CeremonyID,
			Response:   device.Assertion(t, begin.Options),
		},
		service,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("signed assertion without UV admitted", err)
	}
}

func TestPersonalPasskeyEnrollmentCannotSurviveAccountReset(t *testing.T) {
	service, store, principal, _ := mfaFixture(t)
	device := authenticator.New(t, "home.example.test", "https://home.example.test")

	begin, err := service.BeginPasskeyEnrollment(t.Context(), principal, "MacBook")
	if err != nil {
		t.Fatal(err)
	}

	response := device.Registration(t, begin.Options)

	account, err := store.Account(t.Context(), "a")
	if err != nil {
		t.Fatal(err)
	}

	account.AuthVersion++
	store.SetAccountForTest(account)
	principal.AuthVersion = account.AuthVersion

	if err := service.FinishPasskeyEnrollment(
		t.Context(),
		principal,
		begin.CeremonyID,
		response,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("pre-reset enrollment admitted", err)
	}
}

func TestLastPersonalPasskeyCannotBeRemoved(t *testing.T) {
	service, store, principal, _ := mfaFixture(t)

	device, principal := enrollPersonalPasskey(t, service, store, principal)

	if err := service.RemovePasskey(
		t.Context(),
		principal,
		base64.RawURLEncoding.EncodeToString(device.CredentialID),
	); !errors.Is(
		err,
		identity.ErrLastMFA,
	) {
		t.Fatalf("last personal passkey removed: %v", err)
	}
}

func TestRecoveryRegenerationRequiresRecentProofAndActiveMFA(t *testing.T) {
	service, store, principal, now := mfaFixture(t)

	if _, err := service.RegenerateRecoveryCodes(
		t.Context(),
		principal,
	); !errors.Is(
		err,
		identity.ErrLastMFA,
	) {
		t.Fatal("recovery-only state regenerated indefinitely", err)
	}

	_, principal = enrollPersonalPasskey(t, service, store, principal)

	codes, err := service.RegenerateRecoveryCodes(t.Context(), principal)

	if err != nil || len(codes) != 10 {
		t.Fatal("new recovery set unavailable", err)
	}

	factor := identity.FactorContext{
		AccountScope: identity.AccountScope{
			AccountID:   "a",
			AuthVersion: principal.AuthVersion,
			Purpose:     identity.SessionAdmin,
		},
		Binding: sha256.Sum256([]byte("password-proof")),
	}

	if method, err := service.VerifySecondFactor(
		t.Context(),
		factor,
		identity.SecondFactorProof{Method: "recovery", Code: codes[0]},
	); err != nil ||
		method != "recovery" {
		t.Fatal("recovery proof rejected after password", err)
	}

	if _, err := service.VerifySecondFactor(
		t.Context(),
		factor,
		identity.SecondFactorProof{Method: "recovery", Code: codes[0]},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("recovery code reused", err)
	}

	replacement, err := service.RegenerateRecoveryCodes(t.Context(), principal)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.VerifySecondFactor(
		t.Context(),
		factor,
		identity.SecondFactorProof{Method: "recovery", Code: codes[1]},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("replaced recovery code remained valid", err)
	}

	stale := principal
	stale.AuthenticatedAt = now.Add(-5 * time.Minute)

	if _, err := service.RegenerateRecoveryCodes(
		t.Context(),
		stale,
	); !errors.Is(
		err,
		identity.ErrRecentAuthentication,
	) {
		t.Fatal("old session regenerated recovery codes", err)
	}

	if _, err := service.VerifySecondFactor(
		t.Context(),
		factor,
		identity.SecondFactorProof{Method: "recovery", Code: replacement[0]},
	); err != nil {
		t.Fatal("rejected regeneration changed code set", err)
	}
}

func TestSignInMethodsRequireBoundCurrentPasswordProof(t *testing.T) {
	service, store, principal, _ := mfaFixture(t)

	_, principal = enrollPersonalPasskey(t, service, store, principal)
	factor := identity.FactorContext{
		AccountScope: identity.AccountScope{
			AccountID:   "a",
			AuthVersion: principal.AuthVersion,
			Purpose:     identity.SessionAdmin,
		},
		Binding: sha256.Sum256([]byte("password-proof")),
	}

	methods, err := service.SignInMethods(t.Context(), factor)

	if err != nil || !methods.Passkey || methods.TOTP || methods.Recovery {
		t.Fatalf("wrong personal method availability: %+v %v", methods, err)
	}

	factor.Binding = [32]byte{}

	if _, err := service.SignInMethods(
		t.Context(),
		factor,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("anonymous method discovery admitted", err)
	}

	factor.Binding = sha256.Sum256([]byte("password-proof"))
	factor.AuthVersion--

	if _, err := service.SignInMethods(
		t.Context(),
		factor,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("stale password proof discovered methods", err)
	}
}
