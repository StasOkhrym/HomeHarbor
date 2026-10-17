package admin

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
