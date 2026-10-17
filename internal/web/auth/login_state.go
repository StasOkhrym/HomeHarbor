package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type loginPageModel struct {
	ReturnToSecurity bool
	FirstRun         bool
	Migration        bool
	OwnerPassword    bool
	SecondFactor     bool
	Methods          identity.SignInMethods
	SetupBlocked     bool
	Unavailable      bool
	CSRF             string
}

func (a *BrowserAuth) loginState(w http.ResponseWriter, r *http.Request) (loginPageModel, int) {
	unavailable := func() (loginPageModel, int) { return loginPageModel{Unavailable: true}, http.StatusServiceUnavailable }
	if a.accounts == nil {
		return unavailable()
	}

	operation, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	owner, err := a.accounts.Account(operation, identity.OwnerAccountID)
	if err != nil || owner.ID != identity.OwnerAccountID || owner.Role != identity.RoleOwner ||
		owner.AuthVersion == 0 {
		return unavailable()
	}
	if owner.Status == identity.AccountActive {
		cookie, err := r.Cookie(preauthCookieName)
		if r.URL.Query().Get("restart") == "1" {
			http.SetCookie(w, expiredPreauthCookie())
			return loginPageModel{}, http.StatusOK
		}
		if err != nil || len(cookie.Value) == 0 || len(cookie.Value) > 128 {
			return loginPageModel{}, http.StatusOK
		}
		if a.passwordLogin == nil || a.factors == nil {
			return unavailable()
		}

		factor, err := a.passwordLogin.SecondFactorContext(operation, cookie.Value)
		if err != nil {
			if !errors.Is(err, identity.ErrInvalidCredential) {
				return unavailable()
			}

			http.SetCookie(w, expiredPreauthCookie())
			return loginPageModel{}, http.StatusOK
		}

		methods, err := a.factors.SignInMethods(operation, factor)
		if err != nil {
			return unavailable()
		}

		return loginPageModel{SecondFactor: true, Methods: methods}, http.StatusOK
	}
	if owner.Status != identity.AccountSetup {
		return unavailable()
	}

	if _, ok := a.sessionToken(r); ok {
		principal, err := a.sessionPrincipal(r.Context(), r)
		if err != nil && !errors.Is(err, identity.ErrInvalidCredential) {
			return unavailable()
		}
		if err == nil && principal.Purpose == identity.SessionMigration &&
			principal.AccountID == owner.ID {
			csrf, err := r.Cookie(csrfCookieName)
			probe := r.Clone(r.Context())
			if err == nil {
				probe.Header.Set(csrfHeaderName, csrf.Value)
			}

			token, _ := a.sessionToken(r)
			if err != nil || !a.validCSRF(probe, token) {
				csrf, err = a.csrfCookie(token, principal.AuthenticatedAt.Add(5*time.Minute))
				if err != nil {
					return unavailable()
				}

				http.SetCookie(w, csrf)
			}

			return loginPageModel{OwnerPassword: true, CSRF: csrf.Value}, http.StatusOK
		}
	}

	if a.setupState == nil {
		return unavailable()
	}

	registered, err := a.setupState.HasCredentials(operation)
	if err != nil {
		return unavailable()
	}
	if registered {
		return loginPageModel{Migration: true}, http.StatusOK
	}
	if !a.bootstrapAllowed(r) {
		return loginPageModel{SetupBlocked: true}, http.StatusForbidden
	}

	return loginPageModel{FirstRun: true}, http.StatusOK
}
