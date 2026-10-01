package httpapi

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sokhrym/go-tunnels/internal/control/identity"
)

const sessionCookieName = "__Host-go_tunnels_admin"

//go:embed templates/login.html
var loginPage []byte

//go:embed static/auth-ui.js
var loginScript []byte

// PasskeyCeremonies is the HTTP layer's narrow view of WebAuthn state.
type PasskeyCeremonies interface {
	BeginBootstrap(context.Context) (identity.BeginCeremony, error)
	FinishBootstrap(context.Context, string, []byte) (webauthn.Credential, error)
	BeginLogin(context.Context) (identity.BeginCeremony, error)
	FinishLogin(context.Context, string, []byte) (webauthn.Credential, error)
}

// AdminSessions keeps opaque session and recovery credentials out of handlers.
type AdminSessions interface {
	GenerateRecoveryCodes(context.Context, int) ([]string, error)
	ConsumeRecoveryCode(context.Context, string) error
	CreateSession(context.Context, time.Duration) (identity.IssuedSession, error)
	ValidateSession(context.Context, string) (identity.Session, error)
	RevokeSession(context.Context, string) error
}

// BrowserAuthConfig contains runtime-only secrets after file/env resolution.
type BrowserAuthConfig struct {
	Origin     string
	SigningKey []byte
	SessionTTL time.Duration
	Auditor    AuthAuditor
	SetupState PasskeyState
}

// PasskeyState reads durable setup state without starting a WebAuthn ceremony.
// Rendering the login page must not consume Redis quota or create challenges.
type PasskeyState interface {
	HasCredentials(context.Context) (bool, error)
}

// AuthAuditor records outcomes without receiving credential material.
type AuthAuditor interface {
	RecordIdentity(context.Context, string, bool) error
}

// BrowserAuth owns browser credential transport, cookies, Origin checks, and CSRF.
type BrowserAuth struct {
	origin     string
	signingKey []byte
	sessionTTL time.Duration
	passkeys   PasskeyCeremonies
	sessions   AdminSessions
	auditor    AuthAuditor
	setupState PasskeyState
}

// NewBrowserAuth rejects weak signing material before serving any auth route.
func NewBrowserAuth(
	config BrowserAuthConfig,
	passkeys PasskeyCeremonies,
	sessions AdminSessions,
) (*BrowserAuth, error) {
	if len(config.SigningKey) < 32 {
		return nil, errors.New("session signing key must be at least 32 bytes")
	}
	if config.SessionTTL <= 0 {
		return nil, errors.New("session TTL must be positive")
	}
	if config.Origin == "" {
		return nil, errors.New("auth origin is required")
	}
	return &BrowserAuth{
		origin:     strings.TrimSuffix(config.Origin, "/"),
		signingKey: append([]byte(nil), config.SigningKey...),
		sessionTTL: config.SessionTTL,
		passkeys:   passkeys,
		sessions:   sessions,
		auditor:    config.Auditor,
		setupState: config.SetupState,
	}, nil
}

// Handler exposes only versioned JSON authentication endpoints.
func (a *BrowserAuth) Handler() http.Handler {
	router := chi.NewRouter()
	router.Get("/login", a.loginPage)
	router.Group(func(write chi.Router) {
		write.Use(a.requireOrigin)
		write.Post("/bootstrap/begin", a.beginBootstrap)
		write.Post("/bootstrap/finish", a.finishBootstrap)
		write.Post("/login/begin", a.beginLogin)
		write.Post("/login/finish", a.finishLogin)
		write.Post("/recovery", a.recoveryLogin)
		write.Post("/logout", a.logout)
	})
	return router
}

// LoginHandler serves the browser entry point separately from the JSON API.
func (a *BrowserAuth) LoginHandler() http.Handler { return http.HandlerFunc(a.loginPage) }

// LoginAssetHandler serves the browser code from the same origin so CSP does
// not need an inline-script exception or a third-party CDN dependency.
func (a *BrowserAuth) LoginAssetHandler() http.Handler { return http.HandlerFunc(a.loginAsset) }

// IsAdmin requires both a valid cookie signature and a live server-side session.
func (a *BrowserAuth) IsAdmin(ctx context.Context, request *http.Request) (bool, error) {
	token, ok := a.sessionToken(request)
	if !ok {
		a.audit(ctx, "admin.auth", false)
		return false, nil
	}
	_, err := a.sessions.ValidateSession(ctx, token)
	if err != nil {
		a.audit(ctx, "admin.auth", false)
	}
	if errors.Is(err, identity.ErrInvalidCredential) {
		return false, nil
	}
	return err == nil, err
}

// AuthorizeMutation additionally binds state-changing requests to their CSRF cookie.
func (a *BrowserAuth) AuthorizeMutation(ctx context.Context, request *http.Request) (bool, error) {
	// Protected HTML forms share the same Origin boundary as auth POSTs.
	// A valid CSRF token is not permission to submit from another origin.
	if strings.TrimSuffix(request.Header.Get("Origin"), "/") != a.origin {
		return false, nil
	}
	token, ok := a.sessionToken(request)
	if !ok || !a.validCSRF(request, token) {
		return false, nil
	}
	_, err := a.sessions.ValidateSession(ctx, token)
	if errors.Is(err, identity.ErrInvalidCredential) {
		return false, nil
	}
	return err == nil, err
}

func (a *BrowserAuth) sessionToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", false
	}
	expected := a.sign("session." + parts[0])
	// Constant-time comparison avoids leaking a useful prefix of the signature
	// when an attacker repeatedly submits modified cookies.
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return "", false
	}
	return parts[0], true
}

func (a *BrowserAuth) sessionCookie(session identity.IssuedSession) *http.Cookie {
	value := session.Token + "." + a.sign("session."+session.Token)
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  session.ExpiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (a *BrowserAuth) establishSession(w http.ResponseWriter, ctx context.Context) error {
	session, err := a.sessions.CreateSession(ctx, a.sessionTTL)
	if err != nil {
		return err
	}
	csrf, err := a.csrfCookie(session.Token, session.ExpiresAt)
	if err != nil {
		// A session without its CSRF companion is unusable for mutations but
		// remains valid for reads. Revoke it before returning so an entropy
		// failure cannot leave an orphaned authenticated browser session.
		_ = a.sessions.RevokeSession(ctx, session.Token)
		return err
	}
	http.SetCookie(w, a.sessionCookie(session))
	http.SetCookie(w, csrf)
	return nil
}

func (a *BrowserAuth) requireOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth endpoints accept no cross-origin POSTs. This check protects the
		// unauthenticated ceremony-start endpoints before a CSRF token exists.
		if strings.TrimSuffix(r.Header.Get("Origin"), "/") != a.origin {
			a.audit(r.Context(), "admin.auth", false)
			writeError(w, http.StatusForbidden, "origin not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type loginPageModel struct {
	FirstRun    bool
	Unavailable bool
}

var loginTemplate = template.Must(template.New("login").Parse(string(loginPage)))

func (a *BrowserAuth) loginPage(w http.ResponseWriter, r *http.Request) {
	model := loginPageModel{}
	status := http.StatusOK
	// Unknown setup state must never be interpreted as an unclaimed admin
	// account. The ceremony still performs its own atomic bootstrap check.
	if a.setupState == nil {
		model.Unavailable = true
	} else if registered, err := a.setupState.HasCredentials(r.Context()); err != nil {
		model.Unavailable = true
	} else {
		model.FirstRun = !registered
	}
	if model.Unavailable {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := loginTemplate.Execute(w, model); err != nil {
		slog.ErrorContext(r.Context(), "render login page", "error", err)
	}
}

func (a *BrowserAuth) loginAsset(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
	_, _ = w.Write(loginScript)
}

func (a *BrowserAuth) beginBootstrap(w http.ResponseWriter, r *http.Request) {
	result, err := a.passkeys.BeginBootstrap(r.Context())
	a.writeBegin(w, result, err)
}

func (a *BrowserAuth) beginLogin(w http.ResponseWriter, r *http.Request) {
	result, err := a.passkeys.BeginLogin(r.Context())
	a.writeBegin(w, result, err)
}

func (a *BrowserAuth) writeBegin(w http.ResponseWriter, result identity.BeginCeremony, err error) {
	if err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}
		writeError(w, http.StatusUnauthorized, "ceremony unavailable")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type finishCeremonyRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Response   json.RawMessage `json:"response"`
}

func (a *BrowserAuth) finishBootstrap(w http.ResponseWriter, r *http.Request) {
	var input finishCeremonyRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if _, err := a.passkeys.FinishBootstrap(r.Context(), input.CeremonyID, input.Response); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}
		a.audit(r.Context(), "admin.bootstrap", false)
		writeError(w, http.StatusUnauthorized, "invalid ceremony")
		return
	}
	codes, err := a.sessions.GenerateRecoveryCodes(r.Context(), 10)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create recovery codes")
		return
	}
	if err = a.establishSession(w, r.Context()); err != nil {
		a.writeSessionError(w, err)
		return
	}
	a.audit(r.Context(), "admin.bootstrap", true)
	// Recovery plaintext is deliberately returned only by this bootstrap
	// response; the identity store persists hashes and cannot reconstruct it.
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (a *BrowserAuth) finishLogin(w http.ResponseWriter, r *http.Request) {
	var input finishCeremonyRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	if _, err := a.passkeys.FinishLogin(r.Context(), input.CeremonyID, input.Response); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}
		a.audit(r.Context(), "admin.login", false)
		writeError(w, http.StatusUnauthorized, "invalid credential")
		return
	}
	if err := a.establishSession(w, r.Context()); err != nil {
		a.writeSessionError(w, err)
		return
	}
	a.audit(r.Context(), "admin.login", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) recoveryLogin(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := a.sessions.ConsumeRecoveryCode(r.Context(), input.Code); err != nil {
		a.audit(r.Context(), "admin.recovery", false)
		writeError(w, http.StatusUnauthorized, "invalid credential")
		return
	}
	if err := a.establishSession(w, r.Context()); err != nil {
		a.writeSessionError(w, err)
		return
	}
	a.audit(r.Context(), "admin.recovery", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := a.sessionToken(r)
	if !ok || !a.validCSRF(r, token) {
		writeError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}
	if err := a.sessions.RevokeSession(r.Context(), token); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}
		a.audit(r.Context(), "admin.logout", false)
		writeError(w, http.StatusUnauthorized, "invalid session")
		return
	}
	http.SetCookie(w, expiredCookie(sessionCookieName))
	http.SetCookie(w, expiredCookie(csrfCookieName))
	a.audit(r.Context(), "admin.logout", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) writeSessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrSecurityStateUnavailable) {
		writeError(w, http.StatusServiceUnavailable, "security state unavailable")
		return
	}
	writeError(w, http.StatusInternalServerError, "create session")
}

func (a *BrowserAuth) audit(ctx context.Context, action string, success bool) {
	if a.auditor != nil {
		// Authentication availability must not depend on the audit sink, but a
		// failed durable write remains visible to operators in structured logs.
		if err := a.auditor.RecordIdentity(ctx, action, success); err != nil {
			slog.ErrorContext(ctx, "persist identity audit event", "action", action, "error", err)
		}
	}
}

func expiredCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   true,
		HttpOnly: name == sessionCookieName,
		SameSite: http.SameSiteStrictMode,
	}
}
