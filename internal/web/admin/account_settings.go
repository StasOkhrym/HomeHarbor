package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Handler) loadOwnerSettings(r *http.Request, model *Page) int {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok || !principal.CanManageAccounts() || principal.AccountID != identity.OwnerAccountID ||
		principal.AuthVersion == 0 {
		model.Error = "Only the owner can manage administrators and account email."
		return http.StatusForbidden
	}

	age := time.Since(principal.AuthenticatedAt)
	recent := !principal.AuthenticatedAt.IsZero() && age >= 0 && age < 5*time.Minute
	var err error
	switch model.Page {
	case "administrators":
		if s.administrators == nil {
			model.Error = "Administrator accounts could not be loaded. Try again shortly."
			return http.StatusServiceUnavailable
		}

		accounts, loadErr := s.administrators.Administrators(r.Context(), principal)
		err = loadErr
		if err == nil {
			model.Administrators = AccountManagement{
				Ready:        true,
				Recent:       recent,
				EmailEnabled: s.emailEnabled,
				Accounts:     accounts,
			}
			return http.StatusOK
		}
	case "mail":
		if s.mailSettings == nil {
			model.Error = "Account email could not be loaded. Try again shortly."
			return http.StatusServiceUnavailable
		}

		state, loadErr := s.mailSettings.SMTPStatus(r.Context(), principal)
		err = loadErr
		if err == nil {
			model.Mail = MailSettings{Ready: true, Recent: recent, State: state}
			return http.StatusOK
		}
	}

	if errors.Is(err, identity.ErrInvalidCredential) {
		model.Error = "Your owner session changed. Sign in again to continue."
		return http.StatusForbidden
	}

	model.Error = "Account settings could not be loaded. Try again shortly."

	return http.StatusServiceUnavailable
}

func MailTestLabel(state string) string {
	switch state {
	case "never":
		return "No test yet"
	case "pending":
		return "Waiting to send"
	case "sent":
		return "Accepted by SMTP server"
	case "failed":
		return "Delivery failed"
	case "expired":
		return "Test expired"
	case "cancelled":
		return "Test cancelled"
	default:
		return "Unknown"
	}
}
