package identity_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

type factorProof struct{}

func (factorProof) VerifySecondFactor(
	_ context.Context,
	scope identity.AccountScope,
	proof identity.SecondFactorProof,
) (string, error) {
	if scope.AccountID != "a" || scope.AuthVersion != 3 || scope.Purpose != identity.SessionAdmin ||
		proof.Method != "totp" ||
		proof.Code != "123456" {
		return "", identity.ErrInvalidCredential
	}
	return "totp", nil
}

func preauthFixture(
	t *testing.T,
) (*identity.LoginService, *memory.Repository, *identity.Service, *time.Time) {
	t.Helper()
	store := memory.NewRepository()

	store.SetAccountForTest(
		identity.Account{
			ID:           "a",
			Email:        "a@example.test",
			Role:         identity.RoleAdmin,
			Status:       identity.AccountActive,
			AuthVersion:  3,
			PasswordHash: "private-hash",
		},
	)
	now := time.Now().UTC()
	sessions := identity.NewService(store, store, store, func() time.Time { return now }, nil)

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
		func() time.Time { return now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	return login, store, sessions, &now
}

func seedPreauth(t *testing.T, store *memory.Repository, now time.Time, token string) {
	t.Helper()

	if err := store.SavePreauth(
		t.Context(),
		identity.Preauth{
			Hash:        sha256.Sum256([]byte(token)),
			AccountID:   "a",
			AuthVersion: 3,
			CreatedAt:   now,
			ExpiresAt:   now.Add(5 * time.Minute),
		},
	); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordProofCreatesOnlyBoundedPreauth(t *testing.T) {
	login, store, sessions, now := preauthFixture(t)

	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := hasher.Hash(t.Context(), "private long password")
	if err != nil {
		t.Fatal(err)
	}

	store.SetAccountForTest(
		identity.Account{
			ID:           "a",
			Email:        "a@example.test",
			Role:         identity.RoleAdmin,
			Status:       identity.AccountActive,
			AuthVersion:  3,
			PasswordHash: hash,
		},
	)
	for _, input := range []struct{ email, password string }{{"a@example.test", "wrong password"}, {"missing@example.test", "private long password"}} {
		if _, err := login.Password(
			t.Context(),
			input.email,
			input.password,
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("wrong/missing password granted proof: %v", err)
		}
	}

	issued, err := login.Password(t.Context(), " A@EXAMPLE.TEST ", "private long password")
	if err != nil {
		t.Fatal(err)
	}

	if issued.Token == "" || issued.ExpiresAt.Sub(*now) != 5*time.Minute {
		t.Fatal("preauth missing or unbounded")
	}

	if _, err := sessions.ValidateSession(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("password preauth became an admin session")
	}
}

func TestPreauthRequiresCurrentAccountAndExpires(t *testing.T) {
	for _, change := range []string{"epoch", "expiry"} {
		t.Run(change, func(t *testing.T) {
			login, store, _, now := preauthFixture(t)

			seedPreauth(t, store, *now, "preauth")
			if change == "expiry" {
				*now = now.Add(5 * time.Minute)
			} else {
				store.SetAccountForTest(
					identity.Account{
						ID:           "a",
						Email:        "a@example.test",
						Role:         identity.RoleAdmin,
						Status:       identity.AccountActive,
						AuthVersion:  4,
						PasswordHash: "hash",
					},
				)
			}

			if _, err := login.Complete(
				t.Context(),
				"preauth",
				identity.SecondFactorProof{Method: "totp", Code: "123456"},
				factorProof{},
			); !errors.Is(
				err,
				identity.ErrInvalidCredential,
			) {
				t.Fatalf("stale preauth admitted: %v", err)
			}
		})
	}
}

func TestPreauthAttemptsAreBoundedAndSuccessConsumedOnce(t *testing.T) {
	login, store, sessions, now := preauthFixture(t)

	seedPreauth(t, store, *now, "exhausted")
	for range 5 {
		if _, err := login.Complete(
			t.Context(),
			"exhausted",
			identity.SecondFactorProof{Method: "totp", Code: "wrong"},
			factorProof{},
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatal("wrong factor admitted")
		}
	}

	if _, err := login.Complete(
		t.Context(),
		"exhausted",
		identity.SecondFactorProof{Method: "totp", Code: "123456"},
		factorProof{},
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("sixth attempt admitted")
	}

	seedPreauth(t, store, *now, "fifth")
	for range 4 {
		_, _ = login.Complete(
			t.Context(),
			"fifth",
			identity.SecondFactorProof{Method: "totp", Code: "wrong"},
			factorProof{},
		)
	}

	issued, err := login.Complete(
		t.Context(),
		"fifth",
		identity.SecondFactorProof{Method: "totp", Code: "123456"},
		factorProof{},
	)
	if err != nil {
		t.Fatal("fifth attempt rejected", err)
	}

	if principal, err := sessions.ValidateSession(
		t.Context(),
		issued.Token,
	); err != nil || principal.AccountID != "a" ||
		!principal.CanManageNetwork() {
		t.Fatalf("MFA did not issue personal session: %+v %v", principal, err)
	}

	seedPreauth(t, store, *now, "competing")
	var successes atomic.Int32
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			if _, err := login.Complete(
				t.Context(),
				"competing",
				identity.SecondFactorProof{Method: "totp", Code: "123456"},
				factorProof{},
			); err == nil {
				successes.Add(1)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("concurrent completions=%d", successes.Load())
	}
}

type failingPreauth struct {
	identity.PreauthRepository
	phase string
}

func (s failingPreauth) AttemptPreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	if s.phase == "attempt" {
		return identity.Preauth{}, errors.New("private Redis diagnostic")
	}

	return s.PreauthRepository.AttemptPreauth(ctx, hash, now)
}

func (s failingPreauth) ConsumePreauth(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (identity.Preauth, error) {
	if s.phase == "consume" {
		return identity.Preauth{}, errors.New("private Redis diagnostic")
	}

	return s.PreauthRepository.ConsumePreauth(ctx, hash, now)
}

type unavailableSessionIssuer struct{}

func (unavailableSessionIssuer) CreateSession(
	context.Context,
	identity.SessionRequest,
) (identity.IssuedSession, error) {
	return identity.IssuedSession{}, identity.ErrSecurityStateUnavailable
}

func TestPreauthStorageFailureCannotIssueSession(t *testing.T) {
	for _, phase := range []string{"attempt", "consume", "session"} {
		t.Run(phase, func(t *testing.T) {
			_, store, sessions, now := preauthFixture(t)

			seedPreauth(t, store, *now, "preauth")

			hasher, err := identity.NewPasswordHasher(1)
			if err != nil {
				t.Fatal(err)
			}

			var issuer identity.SessionIssuer = sessions
			if phase == "session" {
				issuer = unavailableSessionIssuer{}
			}

			login, err := identity.NewLoginService(
				identity.LoginConfig{SessionTTL: time.Hour},
				store,
				failingPreauth{PreauthRepository: store, phase: phase},
				issuer,
				hasher,
				func() time.Time { return *now },
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}

			issued, err := login.Complete(
				t.Context(),
				"preauth",
				identity.SecondFactorProof{Method: "totp", Code: "123456"},
				factorProof{},
			)

			if !errors.Is(err, identity.ErrSecurityStateUnavailable) || issued.Token != "" ||
				err.Error() != "security state unavailable" {
				t.Fatalf("storage failure granted session/leaked diagnostics: %+v %v", issued, err)
			}

			if phase == "session" {
				retry, err := identity.NewLoginService(
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

				if _, err := retry.Complete(
					t.Context(),
					"preauth",
					identity.SecondFactorProof{Method: "totp", Code: "123456"},
					factorProof{},
				); !errors.Is(
					err,
					identity.ErrInvalidCredential,
				) {
					t.Fatalf("ambiguous session failure reopened consumed proof: %v", err)
				}
			}
		})
	}
}
