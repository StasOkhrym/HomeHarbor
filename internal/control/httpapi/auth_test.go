package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

type fakeSessions struct {
	session  identity.IssuedSession
	valid    string
	recovery string
	revoked  string
	failure  error
}

func (f *fakeSessions) CreateSession(
	context.Context,
	time.Duration,
) (identity.IssuedSession, error) {
	return f.session, f.failure
}

func (f *fakeSessions) ValidateSession(_ context.Context, token string) (identity.Session, error) {
	if f.failure != nil {
		return identity.Session{}, f.failure
	}
	if token != f.valid || !time.Now().Before(f.session.ExpiresAt) {
		return identity.Session{}, identity.ErrInvalidCredential
	}
	return identity.Session{ExpiresAt: f.session.ExpiresAt}, nil
}

func (f *fakeSessions) RevokeSession(_ context.Context, token string) error {
	f.revoked = token
	return f.failure
}

func (f *fakeSessions) ConsumeRecoveryCode(_ context.Context, code string) error {
	if code != f.recovery {
		return identity.ErrInvalidCredential
	}
	return nil
}

func (f *fakeSessions) GenerateRecoveryCodes(context.Context, int) ([]string, error) {
	return []string{"save-once"}, nil
}

type fakePasskeys struct{}

func (fakePasskeys) BeginBootstrap(context.Context) (identity.BeginCeremony, error) {
	return identity.BeginCeremony{}, nil
}

func (fakePasskeys) FinishBootstrap(context.Context, string, []byte) (webauthn.Credential, error) {
	return webauthn.Credential{}, nil
}

func (fakePasskeys) BeginLogin(context.Context) (identity.BeginCeremony, error) {
	return identity.BeginCeremony{}, nil
}

func (fakePasskeys) FinishLogin(context.Context, string, []byte) (webauthn.Credential, error) {
	return webauthn.Credential{}, nil
}

func newBrowserAuthTest(t *testing.T) (*BrowserAuth, *fakeSessions) {
	t.Helper()
	expires := time.Now().Add(time.Hour).UTC()
	sessions := &fakeSessions{
		session:  identity.IssuedSession{Token: "opaque-session", ExpiresAt: expires},
		valid:    "opaque-session",
		recovery: "recover-me",
	}
	auth, err := NewBrowserAuth(
		BrowserAuthConfig{
			Origin:     "https://tunnel.example.com",
			SigningKey: []byte(strings.Repeat("k", 32)),
			SessionTTL: time.Hour,
		},
		fakePasskeys{},
		sessions,
	)
	if err != nil {
		t.Fatal(err)
	}
	return auth, sessions
}

func TestRecoveryLoginSetsHardenedCookies(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)
	req := httptest.NewRequest(
		http.MethodPost,
		"/recovery",
		strings.NewReader(`{"code":"recover-me"}`),
	)
	req.Header.Set("Origin", "https://tunnel.example.com")
	rec := httptest.NewRecorder()

	auth.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()

	if len(cookies) != 2 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	if cookies[0].Name != "__Host-homeharbor_admin" || cookies[1].Name != "__Host-homeharbor_csrf" {
		t.Fatalf("cookie names = %q, %q", cookies[0].Name, cookies[1].Name)
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie is not hardened: %#v", cookies[0])
	}
	if cookies[1].HttpOnly || !cookies[1].Secure || cookies[1].SameSite != http.SameSiteStrictMode {
		t.Fatalf("csrf cookie attributes: %#v", cookies[1])
	}
}

func TestBrowserSessionOutageReturns503WithoutIssuingCookies(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			auth, sessions := newBrowserAuthTest(t)
			sessions.failure = identity.ErrSecurityStateUnavailable
			server := mustTestServer(
				nil,
				auth,
				Dependencies{
					Browser: BrowserDependencies{
						API:                auth.Handler(),
						LoginPage:          auth.LoginHandler(),
						LoginAsset:         auth.LoginAssetHandler(),
						MutationAuthorizer: auth.AuthorizeMutation,
					},
				},
			)
			path := "/api/v1/admin/devices"
			body := ""
			if method == http.MethodPost {
				path, body = "/api/v1/auth/login/finish", `{"ceremony_id":"id","response":{}}`
			}
			request := httptest.NewRequest(method, path, strings.NewReader(body))
			request.Header.Set("Origin", "https://tunnel.example.com")
			request.AddCookie(auth.sessionCookie(sessions.session))
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable ||
				len(response.Result().Cookies()) != 0 {
				t.Fatalf(
					"outage status=%d cookies=%v body=%s",
					response.Code,
					response.Result().Cookies(),
					response.Body.String(),
				)
			}
		})
	}
}

func TestSignedSessionRejectsTamperingAndExpiry(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	cookie := auth.sessionCookie(sessions.session)
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	if authorized, err := auth.IsAdmin(req.Context(), req); !authorized || err != nil {
		t.Fatal("valid session rejected")
	}
	cookie.Value += "x"
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	if authorized, err := auth.IsAdmin(req.Context(), req); authorized || err != nil {
		t.Fatal("tampered cookie accepted")
	}
	sessions.session.ExpiresAt = time.Now().Add(-time.Second)
	cookie = auth.sessionCookie(sessions.session)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	if authorized, err := auth.IsAdmin(req.Context(), req); authorized || err != nil {
		t.Fatal("expired session accepted")
	}
}

func TestCSRFRejectsMismatchAndLogoutRevokesSession(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	sessionCookie := auth.sessionCookie(sessions.session)
	csrfCookie, err := auth.csrfCookie(sessions.session.Token, sessions.session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("Origin", "https://tunnel.example.com")
	req.Header.Set(csrfHeaderName, "wrong")
	rec := httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatch status = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	req.Header.Set("Origin", "https://tunnel.example.com")
	req.Header.Set(csrfHeaderName, csrfCookie.Value)
	rec = httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || sessions.revoked != sessions.session.Token {
		t.Fatalf("logout status=%d revoked=%q", rec.Code, sessions.revoked)
	}
}

func TestCSRFAcceptsSameOriginHTMLFormToken(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	sessionCookie := auth.sessionCookie(sessions.session)
	csrfCookie, err := auth.csrfCookie(sessions.session.Token, sessions.session.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"_csrf": {csrfCookie.Value}}
	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://tunnel.example.com")
	req.AddCookie(sessionCookie)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	auth.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || sessions.revoked != sessions.session.Token {
		t.Fatalf("form logout status=%d revoked=%q", rec.Code, sessions.revoked)
	}
}

func TestAuthRejectsDisallowedOrigin(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)
	req := httptest.NewRequest(
		http.MethodPost,
		"/recovery",
		strings.NewReader(`{"code":"recover-me"}`),
	)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()

	auth.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestBootstrapReturnsRecoveryCodesOnlyOnce(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)

	body, _ := json.Marshal(map[string]any{"ceremony_id": "id", "response": json.RawMessage(`{}`)})
	req := httptest.NewRequest(
		http.MethodPost,
		"/bootstrap/finish",
		strings.NewReader(string(body)),
	)
	req.Header.Set("Origin", "https://tunnel.example.com")
	rec := httptest.NewRecorder()

	auth.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "save-once") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCSRFCookieCreationReturnsRandomnessFailure(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)
	previous := readRandom
	readRandom = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { readRandom = previous })
	if _, err := auth.csrfCookie("session", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("csrfCookie() error = nil")
	}
}

func TestEstablishSessionRevokesSessionWhenCSRFSetupFails(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	previous := readRandom
	readRandom = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	t.Cleanup(func() { readRandom = previous })

	recorder := httptest.NewRecorder()
	if err := auth.establishSession(recorder, context.Background()); err == nil {
		t.Fatal("establishSession() error=nil")
	}
	if sessions.revoked != sessions.session.Token {
		t.Fatalf("revoked session=%q, want %q", sessions.revoked, sessions.session.Token)
	}
	if cookies := recorder.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("cookies=%#v, want none after failed setup", cookies)
	}
}

func TestLoginPageUsesLocalScriptAsset(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)
	recorder := httptest.NewRecorder()

	auth.LoginHandler().
		ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/admin/login", nil))

	if strings.Contains(recorder.Body.String(), "<script>") ||
		!strings.Contains(recorder.Body.String(), "/assets/login.js") {
		t.Fatalf("login page contains inline or missing script: %s", recorder.Body.String())
	}

	asset := httptest.NewRecorder()

	auth.LoginAssetHandler().
		ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/login.js", nil))

	if asset.Code != http.StatusOK ||
		!strings.Contains(asset.Body.String(), "navigator.credentials") {
		t.Fatalf("login asset status=%d body=%s", asset.Code, asset.Body.String())
	}
}
