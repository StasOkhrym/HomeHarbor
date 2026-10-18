package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

// MFAActions is account security behavior, without storage or cookie mechanics.
type MFAActions interface {
	identity.SecondFactorVerifier
	SignInMethods(context.Context, identity.FactorContext) (identity.SignInMethods, error)
	BeginPasskeyLogin(context.Context, identity.FactorContext) (identity.BeginCeremony, error)
	BeginPasskeyEnrollment(
		context.Context,
		identity.Principal,
		string,
	) (identity.BeginCeremony, error)
	FinishPasskeyEnrollment(context.Context, identity.Principal, string, []byte) error
	RemovePasskey(context.Context, identity.Principal, string) error
	BeginTOTP(context.Context, identity.Principal) (identity.TOTPEnrollment, error)
	ConfirmTOTP(context.Context, identity.Principal, string) error
	RemoveTOTP(context.Context, identity.Principal) error
	RegenerateRecoveryCodes(context.Context, identity.Principal) ([]string, error)
}

// AccountHandler must be mounted behind the normal admin session, Origin and
// CSRF middleware. It also requires the verified typed principal at its seam.
func (a *BrowserAuth) AccountHandler() http.Handler {
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			principal, ok := identity.PrincipalFromContext(r.Context())
			if !ok || !principal.CanManageNetwork() {
				httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
				return
			}
			if a.factors == nil {
				httpresponse.WriteError(
					w,
					http.StatusServiceUnavailable,
					"account security unavailable",
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	a.registerAccountMailRoutes(router)
	router.Post("/totp/begin", func(w http.ResponseWriter, r *http.Request) {
		principal, _ := identity.PrincipalFromContext(r.Context())
		enrollment, err := a.factors.BeginTOTP(r.Context(), principal)
		if err != nil {
			a.writeAccountError(w, err)
			return
		}
		httpresponse.WriteJSON(w, http.StatusOK, enrollment)
	})
	router.Post("/totp/confirm", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Code string `json:"code"`
		}
		if !httpresponse.DecodeJSON(w, r, &input) {
			return
		}
		principal, _ := identity.PrincipalFromContext(r.Context())
		a.finishFactorChange(
			w,
			r,
			"admin.totp_added",
			a.factors.ConfirmTOTP(r.Context(), principal, input.Code),
		)
	})
	router.Post("/totp/remove", func(w http.ResponseWriter, r *http.Request) {
		principal, _ := identity.PrincipalFromContext(r.Context())
		a.finishFactorChange(
			w,
			r,
			"admin.totp_removed",
			a.factors.RemoveTOTP(r.Context(), principal),
		)
	})
	router.Post("/passkeys/begin", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name string `json:"name"`
		}
		if !httpresponse.DecodeJSON(w, r, &input) {
			return
		}
		principal, _ := identity.PrincipalFromContext(r.Context())
		ceremony, err := a.factors.BeginPasskeyEnrollment(r.Context(), principal, input.Name)
		if err != nil {
			a.writeAccountError(w, err)
			return
		}
		httpresponse.WriteJSON(w, http.StatusOK, ceremony)
	})
	router.Post("/passkeys/finish", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CeremonyID string          `json:"ceremony_id"`
			Response   json.RawMessage `json:"response"`
		}
		if !httpresponse.DecodeJSON(w, r, &input) {
			return
		}
		principal, _ := identity.PrincipalFromContext(r.Context())
		a.finishFactorChange(
			w,
			r,
			"admin.passkey_added",
			a.factors.FinishPasskeyEnrollment(
				r.Context(),
				principal,
				input.CeremonyID,
				input.Response,
			),
		)
	})
	router.Post("/passkeys/remove", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			ID string `json:"id"`
		}
		if !httpresponse.DecodeJSON(w, r, &input) {
			return
		}
		principal, _ := identity.PrincipalFromContext(r.Context())
		a.finishFactorChange(
			w,
			r,
			"admin.passkey_removed",
			a.factors.RemovePasskey(r.Context(), principal, input.ID),
		)
	})
	router.Post("/recovery-codes", func(w http.ResponseWriter, r *http.Request) {
		principal, _ := identity.PrincipalFromContext(r.Context())
		codes, err := a.factors.RegenerateRecoveryCodes(r.Context(), principal)
		a.accountAudit(r, "admin.recovery_codes_replaced", err)
		if err != nil {
			a.writeAccountError(w, err)
			return
		}
		httpresponse.WriteJSON(w, http.StatusOK, map[string]any{"codes": codes})
	})
	return router
}

func (a *BrowserAuth) finishFactorChange(
	w http.ResponseWriter,
	r *http.Request,
	action string,
	err error,
) {
	a.accountAudit(r, action, err)
	if err != nil {
		a.writeAccountError(w, err)
		return
	}
	// The committed account epoch invalidates all existing sessions, including
	// this one. Redis cleanup cannot undo that security boundary.
	if token, ok := a.sessionToken(r); ok {
		if err := a.sessions.RevokeSession(r.Context(), token); err != nil {
			a.logger.WarnContext(r.Context(), "changed-factor session cleanup unavailable")
		}
	}
	http.SetCookie(w, expiredCookie(sessionCookieName))
	http.SetCookie(w, expiredCookie(csrfCookieName))
	http.SetCookie(w, expiredPreauthCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) accountAudit(r *http.Request, action string, err error) {
	principal, _ := identity.PrincipalFromContext(r.Context())
	ctx := principalAuditContext(r.Context(), principal)
	if err != nil {
		facts := audit.FromContext(ctx)
		facts.Reason = "invalid_proof"
		ctx = audit.WithContext(ctx, facts)
	}

	a.audit(ctx, action, err == nil)
}

func (a *BrowserAuth) writeAccountError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrRecentAuthentication):
		httpresponse.WriteError(
			w,
			http.StatusForbidden,
			"sign in again before changing security settings",
		)
	case errors.Is(err, identity.ErrLastMFA):
		httpresponse.WriteError(
			w,
			http.StatusConflict,
			"keep at least one passkey or authenticator",
		)
	case errors.Is(err, identity.ErrFactorExists):
		httpresponse.WriteError(w, http.StatusConflict, "authenticator already configured")
	case errors.Is(err, identity.ErrFactorLimit):
		httpresponse.WriteError(w, http.StatusConflict, "passkey limit reached")
	default:
		a.writeProofError(w, err)
	}
}

func (a *BrowserAuth) beginPersonalPasskey(w http.ResponseWriter, r *http.Request) {
	if a.passwordLogin == nil || a.factors == nil {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "sign-in unavailable")
		return
	}

	cookie, err := r.Cookie(preauthCookieName)
	if err != nil || cookie.Value == "" {
		a.writeProofError(w, identity.ErrInvalidCredential)
		return
	}

	factor, err := a.passwordLogin.SecondFactorContext(r.Context(), cookie.Value)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	ceremony, err := a.factors.BeginPasskeyLogin(r.Context(), factor)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	httpresponse.WriteJSON(w, http.StatusOK, ceremony)
}
