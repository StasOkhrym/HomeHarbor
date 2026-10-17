package identity_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestPasswordHashSaltsAndRejectsWrongPassword(t *testing.T) {
	hasher, err := identity.NewPasswordHasher(2)
	if err != nil {
		t.Fatal(err)
	}

	password := "a long private password "

	first, err := hasher.Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}

	second, err := hasher.Hash(t.Context(), password)
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("passwords shared a salt")
	}

	if err := hasher.Verify(t.Context(), first, password); err != nil {
		t.Fatal(err)
	}

	for _, wrong := range []string{"wrong password", strings.TrimSpace(password)} {
		if err := hasher.Verify(
			t.Context(),
			first,
			wrong,
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("wrong password admitted: %v", err)
		}
	}
}

func TestPasswordHashRejectsUnboundedParameters(t *testing.T) {
	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	for _, encoded := range []string{"", "$argon2id$v=19$m=4294967295,t=3,p=1$c2FsdA$aGFzaA", "$argon2id$v=19$m=65536,t=999,p=1$c2FsdA$aGFzaA", strings.Repeat("x", 513)} {
		if err := hasher.Verify(
			t.Context(),
			encoded,
			"private password",
		); !errors.Is(
			err,
			identity.ErrInvalidCredential,
		) {
			t.Fatalf("invalid hash accepted: %v", err)
		}
	}
}

func TestPasswordHashHonorsCancelledAdmission(t *testing.T) {
	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	cancel()

	if _, err := hasher.Hash(ctx, "private password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled hashing admitted: %v", err)
	}
}

func TestPasswordRulesPreserveSpacesAndBoundInputs(t *testing.T) {
	for _, password := range []string{"short", strings.Repeat("a", 1025), string([]byte{0xff})} {
		if err := identity.ValidateNewPassword(password); err == nil {
			t.Fatal("invalid new password admitted")
		}
	}

	for _, password := range []string{" twelve chars ", "надійний довгий пароль"} {
		if err := identity.ValidateNewPassword(password); err != nil {
			t.Fatal(err)
		}
	}
}
