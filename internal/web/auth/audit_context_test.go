package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type proofAudit struct {
	facts   audit.Context
	success bool
}

func (p *proofAudit) RecordIdentity(ctx context.Context, _ string, success bool) error {
	p.facts = audit.FromContext(ctx).Safe()
	p.success = success

	return nil
}

type verifiedLegacyPasskey struct{}

func (verifiedLegacyPasskey) BeginBootstrap(context.Context) (identity.BeginCeremony, error) {
	return identity.BeginCeremony{}, nil
}

func (verifiedLegacyPasskey) BeginLogin(context.Context) (identity.BeginCeremony, error) {
	return identity.BeginCeremony{}, nil
}

func (verifiedLegacyPasskey) FinishBootstrap(
	context.Context,
	string,
	[]byte,
) (webauthn.Credential, error) {
	return webauthn.Credential{}, nil
}

func (verifiedLegacyPasskey) FinishLogin(
	context.Context,
	string,
	[]byte,
) (webauthn.Credential, error) {
	return webauthn.Credential{}, nil
}

func TestLegacyProofAuditIdentifiesOwnerWithoutClaimingPassword(t *testing.T) {
	capture := &proofAudit{}
	auth, err := NewBrowserAuth(
		BrowserAuthConfig{
			Origin:     "https://home.example.test",
			SigningKey: []byte(strings.Repeat("k", 32)),
			SessionTTL: time.Hour,
			Auditor:    capture,
		},
		verifiedLegacyPasskey{},
		&entropySessions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/login/finish",
		strings.NewReader(`{"ceremony_id":"public-id","response":{}}`),
	)
	request.Header.Set("Origin", "https://home.example.test")
	response := httptest.NewRecorder()

	auth.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || !capture.success ||
		capture.facts.ActorID != identity.OwnerAccountID ||
		capture.facts.Authentication != "passkey" {
		t.Fatalf(
			"legacy proof identity missing or overstated: status%d %+v",
			response.Code,
			capture.facts,
		)
	}
}

func TestLogoutAuditUsesValidatedPersonalAccount(t *testing.T) {
	capture := &proofAudit{}
	sessions := &entropySessions{
		principal: identity.Principal{
			AccountID:   "admin-a",
			Email:       "a@example.test",
			Role:        identity.RoleAdmin,
			Purpose:     identity.SessionAdmin,
			AuthVersion: 3,
			Method:      "totp",
		},
	}
	auth, err := NewBrowserAuth(
		BrowserAuthConfig{
			Origin:     "https://home.example.test",
			SigningKey: []byte(strings.Repeat("k", 32)),
			SessionTTL: time.Hour,
			Auditor:    capture,
		},
		nil,
		sessions,
	)
	if err != nil {
		t.Fatal(err)
	}

	issued := identity.IssuedSession{
		Token:     "personal-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}

	csrf, err := auth.csrfCookie(issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/logout", nil)
	request.Header.Set("Origin", "https://home.example.test")
	request.Header.Set("X-CSRF-Token", csrf.Value)
	request.AddCookie(auth.sessionCookie(issued))
	request.AddCookie(csrf)
	response := httptest.NewRecorder()

	auth.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || sessions.revoked != issued.Token ||
		!capture.success ||
		capture.facts.ActorID != "admin-a" ||
		capture.facts.ActorName != "a@example.test" ||
		capture.facts.Authentication != "password_totp" {
		t.Fatalf("logout lost personal actor: status%d %+v", response.Code, capture.facts)
	}

	expired := map[string]bool{}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Value == "" && cookie.MaxAge < 0 {
			expired[cookie.Name] = true
		}
	}

	for _, name := range []string{sessionCookieName, csrfCookieName, preauthCookieName, enrollmentCookieName} {
		if !expired[name] {
			t.Fatal("browser authentication proof survived logout", name)
		}
	}
}
