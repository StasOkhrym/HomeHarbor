package admin

import (
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
	factors, err := s.accountSecurity.Factors(r.Context(), principal)
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
		Ready:     true,
		Recent:    age >= 0 && age < 5*time.Minute,
		Email:     principal.Email,
		Role:      string(principal.Role),
		Factors:   factors,
		CanRemove: count > 1,
	}
	return http.StatusOK
}
