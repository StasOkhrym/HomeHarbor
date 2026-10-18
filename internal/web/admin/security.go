package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Handler) loadAccountSecurity(r *http.Request, model *Page) int {
	if s.accountSecurity == nil {
		return http.StatusOK
	}

	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || !principal.CanManageNetwork() {
		return http.StatusUnauthorized
	}

	operation, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var account identity.Account
	if s.accounts != nil {
		var err error

		account, err = s.accounts.Account(operation, principal.AccountID)
		if err != nil {
			model.Error = "Account security could not be loaded. Try again shortly."
			return http.StatusServiceUnavailable
		}

		scope := identity.AccountScope{
			AccountID:   principal.AccountID,
			AuthVersion: principal.AuthVersion,
			Purpose:     principal.Purpose,
		}
		if !scope.Allows(account) || account.Role != principal.Role ||
			account.Email != principal.Email {
			model.Error = "Your account session changed. Sign in again."
			return http.StatusUnauthorized
		}
	}

	factors, err := s.accountSecurity.Factors(operation, principal)
	if err != nil {
		model.Error = "Account security could not be loaded. Try again shortly."
		return http.StatusServiceUnavailable
	}

	count := len(factors.Passkeys)
	if factors.TOTP {
		count++
	}

	age := time.Since(principal.AuthenticatedAt)
	model.Security = Security{
		Ready:            true,
		EmailStatusKnown: s.accounts != nil,
		EmailVerified:    account.EmailVerifiedAt != nil,
		EmailEnabled:     s.emailEnabled,
		SessionStartedAt: principal.AuthenticatedAt,
		SessionMethod:    sessionMethodLabel(principal.Method),
		Recent:           age >= 0 && age < 5*time.Minute,
		Email:            principal.Email,
		Role:             string(principal.Role),
		Factors:          factors,
		CanRemove:        count > 1,
	}

	return http.StatusOK
}

func sessionMethodLabel(method string) string {
	switch method {
	case "totp":
		return "Password + authenticator"
	case "passkey":
		return "Password + passkey"
	case "recovery":
		return "Password + recovery code"
	default:
		return "Verified sign-in"
	}
}
