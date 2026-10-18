package admin

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type personalFactorReader struct {
	principal identity.Principal
	err       error
}

func (s *personalFactorReader) Factors(
	_ context.Context,
	p identity.Principal,
) (identity.FactorState, error) {
	s.principal = p
	return identity.FactorState{
		TOTP:                   true,
		RecoveryCodesRemaining: 7,
		Passkeys: []identity.PasskeyInfo{
			{ID: "owned-key", Name: "MacBook <private>", CreatedAt: time.Now()},
		},
	}, s.err
}

func TestSecurityPageShowsOwnedMethodsAndFailClosedAvailability(t *testing.T) {
	reader := &personalFactorReader{}
	handler := NewHandler(Dependencies{AccountSecurity: reader})
	principal := identity.Principal{
		AccountID:       "admin-a",
		Email:           "a@example.test",
		Role:            identity.RoleAdmin,
		AuthVersion:     3,
		Purpose:         identity.SessionAdmin,
		Method:          "totp",
		AuthenticatedAt: time.Now(),
	}
	request := httptest.NewRequest(http.MethodGet, "/security", nil)

	request = request.WithContext(identity.WithPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()

	handler.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusOK || reader.principal.AccountID != "admin-a" {
		t.Fatal("personal factor authority not used", response.Code)
	}

	body := response.Body.String()
	for _, value := range []string{"a@example.test", "MacBook &lt;private&gt;", "7 unused", "data-account-security", "data-totp-remove", "data-passkey-add"} {
		if !strings.Contains(body, value) {
			t.Fatalf("missing %q", value)
		}
	}

	if strings.Contains(body, "not supported by the current API") {
		t.Fatal("obsolete capability statement remained")
	}

	reader.err = errors.New("private SQL failure")
	response = httptest.NewRecorder()

	handler.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "private SQL failure") ||
		strings.Contains(response.Body.String(), "data-passkey-add") {
		t.Fatalf("outage looked editable: %d %s", response.Code, response.Body.String())
	}
}

type securityAccountReader struct {
	account identity.Account
	err     error
}

func (s *securityAccountReader) Account(context.Context, string) (identity.Account, error) {
	return s.account, s.err
}

func TestSecurityShowsLiveEmailConfirmationAndCurrentSession(t *testing.T) {
	reader := &securityAccountReader{
		account: identity.Account{
			ID:           identity.OwnerAccountID,
			Email:        "owner@example.test",
			Role:         identity.RoleOwner,
			Status:       identity.AccountActive,
			AuthVersion:  1,
			PasswordHash: "private-hash",
		},
	}

	handler := NewHandler(
		Dependencies{
			AccountSecurity: &personalFactorReader{},
			Accounts:        reader,
			EmailEnabled:    true,
		},
	).Routes()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, settingsPageRequest("/security", identity.RoleOwner))

	if response.Code != http.StatusOK {
		t.Fatal("current account security unavailable", response.Code)
	}

	for _, label := range []string{"Email not confirmed", "Send confirmation email", "Current session", "Password + authenticator", "Sign out all devices"} {
		if !strings.Contains(html.UnescapeString(response.Body.String()), label) {
			t.Fatal("missing personal security state", label)
		}
	}

	if strings.Contains(response.Body.String(), "private-hash") {
		t.Fatal("account secret projected into security page")
	}

	now := time.Now()
	reader.account.EmailVerifiedAt = &now
	response = httptest.NewRecorder()

	handler.ServeHTTP(response, settingsPageRequest("/security", identity.RoleOwner))

	if !strings.Contains(response.Body.String(), "Email confirmed") ||
		strings.Contains(response.Body.String(), "Send confirmation email") {
		t.Fatal("confirmed email still offers confirmation")
	}

	reader.err = errors.New("PRIVATE_ACCOUNT_READ_ERROR")
	response = httptest.NewRecorder()

	handler.ServeHTTP(response, settingsPageRequest("/security", identity.RoleOwner))

	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "PRIVATE_ACCOUNT") ||
		strings.Contains(response.Body.String(), "data-security-action=") {
		t.Fatal("failed account read remained writable", response.Code)
	}

	reader.err = nil
	reader.account.AuthVersion++
	response = httptest.NewRecorder()

	handler.ServeHTTP(response, settingsPageRequest("/security", identity.RoleOwner))

	if response.Code != http.StatusUnauthorized ||
		strings.Contains(response.Body.String(), "data-security-action=") {
		t.Fatal("stale account epoch showed security controls", response.Code)
	}
}
