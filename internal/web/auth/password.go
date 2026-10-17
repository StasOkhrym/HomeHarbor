package auth

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/httprequest"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

const preauthCookieName = "__Host-homeharbor_preauth"

type PasswordLogin interface {
	Password(context.Context, string, string) (identity.IssuedPreauth, error)
	Complete(
		context.Context,
		string,
		identity.SecondFactorProof,
		identity.SecondFactorVerifier,
	) (identity.IssuedSession, error)
	ConfigureOwner(context.Context, identity.Principal, string, string) error
}

type passwordInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *BrowserAuth) passwordProof(w http.ResponseWriter, r *http.Request) {
	if a.passwordLogin == nil {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "sign-in unavailable")
		return
	}
	var input passwordInput
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}
	http.SetCookie(w, expiredPreauthCookie())
	issued, err := a.passwordLogin.Password(r.Context(), input.Email, input.Password)
	if err != nil {
		a.audit(r.Context(), "admin.login", false)
		a.writeProofError(w, err)
		return
	}
	http.SetCookie(
		w,
		&http.Cookie{
			Name:     preauthCookieName,
			Value:    issued.Token,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Expires:  issued.ExpiresAt,
			MaxAge:   300,
		},
	)
	w.Header().Set("Cache-Control", "no-store")
	httpresponse.WriteJSON(w, http.StatusOK, map[string]string{"next": "second_factor"})
}

func (a *BrowserAuth) factorProof(w http.ResponseWriter, r *http.Request) {
	if a.passwordLogin == nil || a.factors == nil {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "sign-in unavailable")
		return
	}

	cookie, err := r.Cookie(preauthCookieName)
	if err != nil || cookie.Value == "" {
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}

	var proof identity.SecondFactorProof
	if !httpresponse.DecodeJSON(w, r, &proof) {
		return
	}

	issued, err := a.passwordLogin.Complete(r.Context(), cookie.Value, proof, a.factors)
	if err != nil {
		a.audit(r.Context(), "admin.login", false)
		a.writeProofError(w, err)
		return
	}

	principal, err := a.sessions.ValidateSession(r.Context(), issued.Token)
	if err != nil {
		_ = a.sessions.RevokeSession(r.Context(), issued.Token)
		a.writeSessionError(w, err)
		return
	}

	if err := a.setSessionCookies(w, r.Context(), issued); err != nil {
		a.writeSessionError(w, err)
		return
	}

	http.SetCookie(w, expiredPreauthCookie())
	a.audit(principalAuditContext(r.Context(), principal), "admin.login", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) ownerPassword(w http.ResponseWriter, r *http.Request) {
	if a.passwordLogin == nil {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "setup unavailable")
		return
	}

	token, ok := a.sessionToken(r)
	if !ok || !a.validCSRF(r, token) {
		httpresponse.WriteError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	principal, err := a.sessions.ValidateSession(r.Context(), token)
	if err != nil {
		a.writeProofError(w, err)
		return
	}
	if principal.Purpose != identity.SessionMigration {
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}

	var input passwordInput
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	if err := identity.ValidateNewPassword(input.Password); err != nil {
		httpresponse.WriteError(
			w,
			http.StatusBadRequest,
			"use at least 12 characters, at most 1024 bytes",
		)
		return
	}

	if err := a.passwordLogin.ConfigureOwner(
		r.Context(),
		principal,
		input.Email,
		input.Password,
	); err != nil {
		a.writeProofError(w, err)
		return
	}

	// SQL activation already invalidated every migration session. Redis cleanup
	// may fail independently; it cannot turn the committed setup into a retry.
	if err := a.sessions.RevokeSession(r.Context(), token); err != nil {
		a.logger.WarnContext(r.Context(), "migration session cleanup unavailable")
	}

	http.SetCookie(w, expiredCookie(sessionCookieName))
	http.SetCookie(w, expiredCookie(csrfCookieName))
	http.SetCookie(w, expiredPreauthCookie())
	a.audit(principalAuditContext(r.Context(), principal), "admin.account_configured", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) writeProofError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrSecurityStateUnavailable) ||
		errors.Is(err, context.DeadlineExceeded) {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "sign-in unavailable")
		return
	}

	httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
}

func (a *BrowserAuth) bootstrapAllowed(r *http.Request) bool {
	if a.allowRemoteSetup {
		return true
	}

	peer, err := netip.ParseAddr(httprequest.ClientIP(r, nil))
	if err != nil {
		return false
	}

	trusted := false
	for _, prefix := range a.trustedProxyCIDRs {
		if prefix.Contains(peer) {
			trusted = true
			break
		}
	}

	if !trusted &&
		(r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-IP") != "") {
		return false
	}
	if trusted && r.Header.Get("X-Forwarded-For") == "" {
		return false
	}

	client, err := netip.ParseAddr(httprequest.ClientIP(r, a.trustedProxyCIDRs))

	return err == nil && client.Unmap().IsLoopback()
}

// Keep proof cookies private even when an expired-cookie response is generated.
func expiredPreauthCookie() *http.Cookie {
	cookie := expiredCookie(preauthCookieName)
	cookie.HttpOnly = true

	return cookie
}
