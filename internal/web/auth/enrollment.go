package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

const enrollmentCookieName = "__Host-homeharbor_enrollment"

type AccountEnrollment interface {
	Password(context.Context, string, string) (identity.IssuedPreauth, error)
	Context(context.Context, string) (identity.FactorContext, error)
	BeginTOTP(context.Context, string) (identity.TOTPEnrollment, error)
	ConfirmTOTP(context.Context, string, string) error
	BeginPasskey(context.Context, string, string) (identity.BeginCeremony, error)
	FinishPasskey(context.Context, string, string, []byte) error
}

func (a *BrowserAuth) requireEnrollment(w http.ResponseWriter) bool {
	if a.enrollment != nil {
		return true
	}

	a.writeProofError(w, identity.ErrSecurityStateUnavailable)
	return false
}

func (a *BrowserAuth) registerEnrollmentRoutes(router chi.Router) {
	router.Post("/enrollment/password", a.enrollmentPassword)
	router.Group(func(setup chi.Router) {
		setup.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !a.requireEnrollment(w) {
					return
				}

				cookie, err := r.Cookie(enrollmentCookieName)
				if err != nil || len(cookie.Value) != 43 {
					a.writeProofError(w, identity.ErrInvalidCredential)
					return
				}

				next.ServeHTTP(w, r)
			})
		})
		setup.Post("/enrollment/totp/begin", a.beginEnrollmentTOTP)
		setup.Post("/enrollment/totp/confirm", a.confirmEnrollmentTOTP)
		setup.Post("/enrollment/passkey/begin", a.beginEnrollmentPasskey)
		setup.Post("/enrollment/passkey/finish", a.finishEnrollmentPasskey)
	})
}

func (a *BrowserAuth) enrollmentPassword(w http.ResponseWriter, r *http.Request) {
	if !a.requireEnrollment(w) {
		return
	}

	var input passwordInput
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	http.SetCookie(w, expiredEnrollmentCookie())

	issued, err := a.enrollment.Password(r.Context(), input.Email, input.Password)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	http.SetCookie(w, passwordProofCookie(enrollmentCookieName, issued))
	httpresponse.WriteJSON(w, http.StatusOK, map[string]string{"next": "enrollment"})
}

func (a *BrowserAuth) beginEnrollmentTOTP(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie(enrollmentCookieName)
	result, err := a.enrollment.BeginTOTP(r.Context(), cookie.Value)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	httpresponse.WriteJSON(w, http.StatusOK, result)
}

func (a *BrowserAuth) confirmEnrollmentTOTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code string `json:"code"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	a.finishEnrollment(
		w,
		r,
		"totp",
		func(ctx context.Context, token string) error { return a.enrollment.ConfirmTOTP(ctx, token, input.Code) },
	)
}

func (a *BrowserAuth) beginEnrollmentPasskey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	cookie, _ := r.Cookie(enrollmentCookieName)
	result, err := a.enrollment.BeginPasskey(r.Context(), cookie.Value, input.Name)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	httpresponse.WriteJSON(w, http.StatusOK, result)
}

func (a *BrowserAuth) finishEnrollmentPasskey(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	a.finishEnrollment(w, r, "passkey", func(ctx context.Context, token string) error {
		return a.enrollment.FinishPasskey(ctx, token, input.CeremonyID, input.Response)
	})
}

func expiredEnrollmentCookie() *http.Cookie {
	cookie := expiredCookie(enrollmentCookieName)
	cookie.HttpOnly = true

	return cookie
}

func passwordProofCookie(name string, issued identity.IssuedPreauth) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    issued.Token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  issued.ExpiresAt,
		MaxAge:   300,
	}
}

func (a *BrowserAuth) enrollmentSubject(
	ctx context.Context,
	token string,
) (identity.AccountSubject, error) {
	if a.accounts == nil || a.enrollment == nil {
		return identity.AccountSubject{}, identity.ErrSecurityStateUnavailable
	}

	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	factor, err := a.enrollment.Context(operation, token)
	if err != nil {
		return identity.AccountSubject{}, err
	}

	account, err := a.accounts.Account(operation, factor.AccountID)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidCredential) {
			return identity.AccountSubject{}, identity.ErrInvalidCredential
		}

		return identity.AccountSubject{}, identity.ErrSecurityStateUnavailable
	}
	if factor.Purpose != identity.SessionEnrollment || factor.Binding == ([32]byte{}) ||
		!factor.Allows(account) {
		return identity.AccountSubject{}, identity.ErrInvalidCredential
	}

	return account.Subject(), nil
}

func (a *BrowserAuth) finishEnrollment(
	w http.ResponseWriter,
	r *http.Request,
	method string,
	commit func(context.Context, string) error,
) {
	cookie, err := r.Cookie(enrollmentCookieName)
	if err != nil {
		a.writeProofError(w, identity.ErrInvalidCredential)
		return
	}

	ctx := mailProofAuditContext(r.Context())
	facts := audit.FromContext(ctx)
	facts.Authentication = "password_" + method
	ctx = audit.WithContext(ctx, facts)
	subject, err := a.enrollmentSubject(ctx, cookie.Value)
	if err == nil {
		err = commit(ctx, cookie.Value)
	}

	a.auditAccount(ctx, "admin.account_activated", subject, err)
	if err != nil {
		a.writeProofError(w, err)
		return
	}

	// Completing setup never writes an admin cookie. Normal password+MFA login is
	// still required, and the old setup proof is fenced by the committed SQL epoch.
	http.SetCookie(w, expiredEnrollmentCookie())
	w.WriteHeader(http.StatusNoContent)
}
