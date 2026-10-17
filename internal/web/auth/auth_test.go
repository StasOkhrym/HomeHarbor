package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type entropySessions struct {
	revoked   string
	principal identity.Principal
}

func (*entropySessions) GenerateRecoveryCodes(
	context.Context,
	identity.AccountScope,
	int,
) ([]string, error) {
	return nil, nil
}

func (*entropySessions) ConsumeRecoveryCode(context.Context, identity.AccountScope, string) error {
	return nil
}

func (*entropySessions) CreateSession(
	context.Context,
	identity.SessionRequest,
) (identity.IssuedSession, error) {
	return identity.IssuedSession{
		Token:     "issued-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (s *entropySessions) ValidateSession(context.Context, string) (identity.Principal, error) {
	return s.principal, nil
}

func (s *entropySessions) RevokeSession(_ context.Context, token string) error {
	s.revoked = token
	return nil
}

func TestCSRFEntropyFailureRevokesUnusableSession(t *testing.T) {
	sessions := &entropySessions{}
	auth, err := NewBrowserAuth(BrowserAuthConfig{
		Origin: "https://tunnel.example.com", SigningKey: []byte(strings.Repeat("k", 32)),
		SessionTTL: time.Hour,
	}, nil, sessions)
	if err != nil {
		t.Fatal(err)
	}

	previous := readRandom
	readRandom = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { readRandom = previous })

	if _, err := auth.csrfCookie("issued-session", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("csrfCookie() error = nil")
	}

	response := httptest.NewRecorder()

	if err := auth.establishSession(response, context.Background(), "passkey"); err == nil {
		t.Fatal("establishSession() error = nil")
	}

	if sessions.revoked != "issued-session" || len(response.Result().Cookies()) != 0 {
		t.Fatalf(
			"orphan session or cookies: revoked=%q cookies=%v",
			sessions.revoked,
			response.Result().Cookies(),
		)
	}

	if got := response.Code; got != http.StatusOK {
		t.Fatalf("establishSession unexpectedly wrote a response: %d", got)
	}
}
