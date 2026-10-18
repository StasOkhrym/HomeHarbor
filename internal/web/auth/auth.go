package auth

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
	"github.com/StasOkhrym/homeharbor/internal/web/assets"
	websession "github.com/StasOkhrym/homeharbor/internal/web/session"
)

const sessionCookieName = websession.CookieName

var (
	loginPage   = assets.HTML("login.html")
	loginScript = assets.Static("auth-ui.js")
)

// PasskeyCeremonies is the HTTP layer's narrow view of WebAuthn state.
type PasskeyCeremonies interface {
	BeginBootstrap(context.Context) (identity.BeginCeremony, error)
	FinishBootstrap(context.Context, string, []byte) (webauthn.Credential, error)
	BeginLogin(context.Context) (identity.BeginCeremony, error)
	FinishLogin(context.Context, string, []byte) (webauthn.Credential, error)
}

// AdminSessions keeps opaque session and recovery credentials out of handlers.
type AdminSessions interface {
	GenerateRecoveryCodes(context.Context, identity.AccountScope, int) ([]string, error)
	ConsumeRecoveryCode(context.Context, identity.AccountScope, string) error
	CreateSession(context.Context, identity.SessionRequest) (identity.IssuedSession, error)
	ValidateSession(context.Context, string) (identity.Principal, error)
	RevokeSession(context.Context, string) error
}

// BrowserAuthConfig contains runtime-only secrets after file/env resolution.
type BrowserAuthConfig struct {
	Accounts          identity.AccountReader
	PasswordLogin     PasswordLogin
	Factors           MFAActions
	Mail              MailActions
	Enrollment        AccountEnrollment
	EmailEnabled      bool
	AllowRemoteSetup  bool
	TrustedProxyCIDRs []netip.Prefix
	Origin            string
	SigningKey        []byte
	SessionTTL        time.Duration
	Auditor           AuthAuditor
	SetupState        PasskeyState
	Logger            *slog.Logger
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

// BrowserAuth coordinates passkey transport, session liveness and Origin checks.
// Browser cookie and CSRF proof mechanics live in web/session.
type BrowserAuth struct {
	accounts          identity.AccountReader
	passwordLogin     PasswordLogin
	factors           MFAActions
	mail              MailActions
	enrollment        AccountEnrollment
	emailEnabled      bool
	allowRemoteSetup  bool
	trustedProxyCIDRs []netip.Prefix
	origin            string
	codec             *websession.Codec
	sessionTTL        time.Duration
	passkeys          PasskeyCeremonies
	sessions          AdminSessions
	auditor           AuthAuditor
	setupState        PasskeyState
	logger            *slog.Logger
}

// NewBrowserAuth rejects weak signing material before serving any auth route.
func NewBrowserAuth(
	config BrowserAuthConfig,
	passkeys PasskeyCeremonies,
	sessions AdminSessions,
) (*BrowserAuth, error) {
	codec, err := websession.NewCodec(config.SigningKey, func(value []byte) (int, error) {
		return readRandom(value)
	})
	if err != nil {
		return nil, err
	}
	if config.SessionTTL <= 0 {
		return nil, errors.New("session TTL must be positive")
	}
	if config.Origin == "" {
		return nil, errors.New("auth origin is required")
	}
	if (config.EmailEnabled && config.Mail == nil) ||
		(config.Mail != nil) != (config.Enrollment != nil) ||
		(config.Mail != nil && (config.Factors == nil || config.PasswordLogin == nil || config.Accounts == nil)) {
		return nil, errors.New(
			"mail authentication requires account, password, MFA and enrollment capabilities",
		)
	}

	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &BrowserAuth{
		accounts:          config.Accounts,
		passwordLogin:     config.PasswordLogin,
		factors:           config.Factors,
		mail:              config.Mail,
		enrollment:        config.Enrollment,
		emailEnabled:      config.EmailEnabled,
		allowRemoteSetup:  config.AllowRemoteSetup,
		trustedProxyCIDRs: append([]netip.Prefix(nil), config.TrustedProxyCIDRs...),
		origin:            strings.TrimSuffix(config.Origin, "/"),
		codec:             codec,
		sessionTTL:        config.SessionTTL,
		passkeys:          passkeys,
		sessions:          sessions,
		auditor:           config.Auditor,
		setupState:        config.SetupState,
		logger:            logger,
	}, nil
}

// Handler exposes only versioned JSON authentication endpoints.
func (a *BrowserAuth) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	})
	router.Get("/login", a.loginPage)
	router.Group(func(write chi.Router) {
		write.Use(a.requireOrigin)
		write.Post("/bootstrap/begin", a.beginBootstrap)
		write.Post("/bootstrap/finish", a.finishBootstrap)
		write.Post("/login/begin", a.beginLogin)
		write.Post("/login/finish", a.finishLogin)
		write.Post("/recovery", a.recoveryLogin)
		a.registerMailRoutes(write)
		a.registerEnrollmentRoutes(write)
		write.Post("/password", a.passwordProof)
		write.Post("/factor", a.factorProof)
		write.Post("/passkey/begin", a.beginPersonalPasskey)
		write.Post("/owner/password", a.ownerPassword)
		write.Post("/logout", a.logout)
	})
	return router
}

// LoginHandler serves the browser entry point separately from the JSON API.
func (a *BrowserAuth) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if flow, _ := mailFlow(r.URL.Path); flow != "" {
			a.mailPage(w, r)
			return
		}

		a.loginPage(w, r)
	})
}

// LoginAssetHandler serves the browser code from the same origin so CSP does
// not need an inline-script exception or a third-party CDN dependency.
func (a *BrowserAuth) LoginAssetHandler() http.Handler { return http.HandlerFunc(a.loginAsset) }

// AdminPrincipal requires both a signed cookie and current personal account
// authority. Restricted migration proofs can never enter protected admin routes.
func (a *BrowserAuth) AdminPrincipal(
	ctx context.Context,
	request *http.Request,
) (identity.Principal, error) {
	principal, err := a.sessionPrincipal(ctx, request)
	if err != nil {
		return identity.Principal{}, err
	}
	if !principal.CanManageNetwork() {
		a.audit(ctx, "admin.auth", false)
		return identity.Principal{}, identity.ErrInvalidCredential
	}

	return principal, nil
}

func (a *BrowserAuth) sessionPrincipal(
	ctx context.Context,
	request *http.Request,
) (identity.Principal, error) {
	token, ok := a.sessionToken(request)
	if !ok {
		a.audit(ctx, "admin.auth", false)
		return identity.Principal{}, identity.ErrInvalidCredential
	}

	principal, err := a.sessions.ValidateSession(ctx, token)
	if err != nil {
		a.audit(ctx, "admin.auth", false)
		return identity.Principal{}, err
	}

	return principal, nil
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

	principal, err := a.sessions.ValidateSession(ctx, token)
	if errors.Is(err, identity.ErrInvalidCredential) {
		return false, nil
	}

	return err == nil && principal.CanManageNetwork(), err
}

func (a *BrowserAuth) sessionToken(request *http.Request) (string, bool) {
	return a.codec.SessionToken(request)
}

func (a *BrowserAuth) sessionCookie(session identity.IssuedSession) *http.Cookie {
	return a.codec.SessionCookie(session.Token, session.ExpiresAt)
}

func (a *BrowserAuth) establishSession(
	w http.ResponseWriter,
	ctx context.Context,
	method string,
) error {
	session, err := a.sessions.CreateSession(
		ctx,
		identity.SessionRequest{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
			Method:    method,
			TTL:       a.sessionTTL,
		},
	)
	if err != nil {
		return err
	}

	return a.setSessionCookies(w, ctx, session)
}

func (a *BrowserAuth) setSessionCookies(
	w http.ResponseWriter,
	ctx context.Context,
	session identity.IssuedSession,
) error {
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
			httpresponse.WriteError(w, http.StatusForbidden, "origin not allowed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

var loginTemplate = template.Must(template.New("login").Parse(string(loginPage)))

func (a *BrowserAuth) loginPage(w http.ResponseWriter, r *http.Request) {
	model, status := a.loginState(w, r)
	model.ReturnToSecurity = r.URL.Query().Get("return_to") == "security"
	model.EmailEnabled = a.emailEnabled
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	if err := loginTemplate.Execute(w, model); err != nil {
		a.logger.ErrorContext(r.Context(), "render login page", "error", err)
	}
}

func (a *BrowserAuth) loginAsset(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
	_, _ = w.Write(loginScript)
}

func (a *BrowserAuth) beginBootstrap(w http.ResponseWriter, r *http.Request) {
	if !a.bootstrapAllowed(r) {
		httpresponse.WriteError(
			w,
			http.StatusForbidden,
			"owner setup requires loopback or explicit setup mode",
		)
		return
	}

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
			httpresponse.WriteError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}

		httpresponse.WriteError(w, http.StatusUnauthorized, "ceremony unavailable")
		return
	}

	httpresponse.WriteJSON(w, http.StatusOK, result)
}

type finishCeremonyRequest struct {
	CeremonyID string          `json:"ceremony_id"`
	Response   json.RawMessage `json:"response"`
}

func (a *BrowserAuth) finishBootstrap(w http.ResponseWriter, r *http.Request) {
	if !a.bootstrapAllowed(r) {
		httpresponse.WriteError(
			w,
			http.StatusForbidden,
			"owner setup requires loopback or explicit setup mode",
		)
		return
	}

	var input finishCeremonyRequest
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	if _, err := a.passkeys.FinishBootstrap(
		r.Context(),
		input.CeremonyID,
		input.Response,
	); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			httpresponse.WriteError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}

		a.audit(r.Context(), "admin.bootstrap", false)
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid ceremony")
		return
	}

	r = r.WithContext(legacyProofAuditContext(r.Context(), "passkey"))
	codes, err := a.sessions.GenerateRecoveryCodes(
		r.Context(),
		identity.AccountScope{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
		},
		10,
	)
	if err != nil {
		a.writeBootstrapFailure(w, r, err, "bootstrap_recovery_unavailable")
		return
	}

	if err = a.establishSession(w, r.Context(), "passkey"); err != nil {
		a.writeBootstrapFailure(w, r, err, "bootstrap_session_unavailable")
		return
	}

	a.audit(r.Context(), "admin.bootstrap", true)
	// Recovery plaintext is deliberately returned only by this bootstrap
	// response; the identity store persists hashes and cannot reconstruct it.
	httpresponse.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// Registration already committed before these steps. Neither recovery storage
// nor Redis session creation can roll it back; retrying bootstrap is not recovery.
func (a *BrowserAuth) writeBootstrapFailure(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	code string,
) {
	a.audit(r.Context(), "admin.bootstrap", false)
	status := http.StatusInternalServerError
	if errors.Is(err, identity.ErrSecurityStateUnavailable) {
		status = http.StatusServiceUnavailable
	}

	httpresponse.WriteErrorCode(
		w,
		status,
		code,
		"passkey saved; setup incomplete; reload and sign in",
	)
}

func (a *BrowserAuth) finishLogin(w http.ResponseWriter, r *http.Request) {
	var input finishCeremonyRequest
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	if _, err := a.passkeys.FinishLogin(r.Context(), input.CeremonyID, input.Response); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			httpresponse.WriteError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}

		a.audit(r.Context(), "admin.login", false)
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}

	r = r.WithContext(legacyProofAuditContext(r.Context(), "passkey"))
	if err := a.establishSession(w, r.Context(), "passkey"); err != nil {
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
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	if err := a.sessions.ConsumeRecoveryCode(
		r.Context(),
		identity.AccountScope{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
		},
		input.Code,
	); err != nil {
		a.audit(r.Context(), "admin.recovery", false)
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}

	r = r.WithContext(legacyProofAuditContext(r.Context(), "identity_proof"))
	if err := a.establishSession(w, r.Context(), "recovery"); err != nil {
		a.writeSessionError(w, err)
		return
	}

	a.audit(r.Context(), "admin.recovery", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := a.sessionToken(r)
	if !ok || !a.validCSRF(r, token) {
		httpresponse.WriteError(w, http.StatusForbidden, "invalid CSRF token")
		return
	}

	// Audit only the account established by live session authority. Lookup failure
	// must not prevent an otherwise valid CSRF-protected revocation request.
	if principal, err := a.sessions.ValidateSession(
		r.Context(),
		token,
	); err == nil &&
		principal.AccountID != "" {
		r = r.WithContext(principalAuditContext(r.Context(), principal))
	}

	if err := a.sessions.RevokeSession(r.Context(), token); err != nil {
		if errors.Is(err, identity.ErrSecurityStateUnavailable) {
			httpresponse.WriteError(w, http.StatusServiceUnavailable, "security state unavailable")
			return
		}

		a.audit(r.Context(), "admin.logout", false)
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid session")
		return
	}

	http.SetCookie(w, expiredCookie(sessionCookieName))
	http.SetCookie(w, expiredCookie(csrfCookieName))
	http.SetCookie(w, expiredPreauthCookie())
	http.SetCookie(w, expiredEnrollmentCookie())
	a.audit(r.Context(), "admin.logout", true)
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) writeSessionError(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrInvalidCredential) {
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid credential")
		return
	}
	if errors.Is(err, identity.ErrSecurityStateUnavailable) {
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "security state unavailable")
		return
	}

	httpresponse.WriteError(w, http.StatusInternalServerError, "create session")
}

func (a *BrowserAuth) audit(ctx context.Context, action string, success bool) {
	if a.auditor != nil {
		// Authentication availability must not depend on the audit sink, but a
		// failed durable write remains visible to operators in structured logs.
		if err := a.auditor.RecordIdentity(ctx, action, success); err != nil {
			a.logger.ErrorContext(
				ctx, "persist identity audit event", "action", action, "error", err,
			)
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
