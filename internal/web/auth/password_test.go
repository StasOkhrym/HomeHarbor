package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	memory "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
)

var passwordFixture struct {
	sync.Once
	hash string
	err  error
}

func fixturePasswordHash(t *testing.T) string {
	t.Helper()
	passwordFixture.Do(func() {
		var hasher *identity.PasswordHasher
		hasher, passwordFixture.err = identity.NewPasswordHasher(1)
		if passwordFixture.err == nil {
			passwordFixture.hash, passwordFixture.err = hasher.Hash(
				context.Background(),
				"private long password",
			)
		}
	})

	if passwordFixture.err != nil {
		t.Fatal(passwordFixture.err)
	}

	return passwordFixture.hash
}

type verifiedPasswordFactor struct{}

func (verifiedPasswordFactor) VerifySecondFactor(
	_ context.Context,
	scope identity.AccountScope,
	proof identity.SecondFactorProof,
) (string, error) {
	if scope.AccountID != identity.OwnerAccountID || scope.AuthVersion != 2 ||
		scope.Purpose != identity.SessionAdmin ||
		proof.Method != "totp" ||
		proof.Code != "123456" {
		return "", identity.ErrInvalidCredential
	}
	return "totp", nil
}

func personalAuthFixture(
	t *testing.T,
	active bool,
) (*BrowserAuth, *memory.Repository, *identity.Service) {
	t.Helper()
	store := memory.NewRepository()
	if active {
		store.SetAccountForTest(
			identity.Account{
				ID:           identity.OwnerAccountID,
				Email:        "owner@example.test",
				Role:         identity.RoleOwner,
				Status:       identity.AccountActive,
				AuthVersion:  2,
				PasswordHash: fixturePasswordHash(t),
				UserHandle:   []byte("homeharbor-admin-v1"),
			},
		)
	}
	sessions := identity.NewService(store, store, store, time.Now, nil)
	hasher, err := identity.NewPasswordHasher(1)
	if err != nil {
		t.Fatal(err)
	}
	login, err := identity.NewLoginService(
		identity.LoginConfig{SessionTTL: time.Hour},
		store,
		store,
		sessions,
		hasher,
		time.Now,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewBrowserAuth(
		BrowserAuthConfig{
			Origin:        "https://home.example.test",
			SigningKey:    []byte(strings.Repeat("k", 32)),
			SessionTTL:    time.Hour,
			SetupState:    store,
			Accounts:      store,
			PasswordLogin: login,
			Factors:       verifiedPasswordFactor{},
		},
		verifiedLegacyPasskey{},
		sessions,
	)
	if err != nil {
		t.Fatal(err)
	}
	return auth, store, sessions
}

func TestPasswordHTTPRequiresSecondFactorBeforeAdminSession(t *testing.T) {
	auth, _, _ := personalAuthFixture(t, true)
	request := httptest.NewRequest(
		http.MethodPost,
		"/password",
		strings.NewReader(`{"email":"owner@example.test","password":"private long password"}`),
	)
	request.Header.Set("Origin", "https://home.example.test")
	response := httptest.NewRecorder()
	auth.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("password status%d %s", response.Code, response.Body.String())
	}
	var preauth *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			t.Fatal("password minted an admin cookie")
		}
		if cookie.Name == preauthCookieName {
			preauth = cookie
		}
	}
	if preauth == nil || !preauth.HttpOnly || !preauth.Secure ||
		preauth.SameSite != http.SameSiteStrictMode ||
		preauth.MaxAge > 300 ||
		strings.Contains(response.Body.String(), preauth.Value) {
		t.Fatal("preauth proof exposed or unbounded")
	}
	protected := httptest.NewRequest(http.MethodGet, "/admin/", nil)
	protected.AddCookie(preauth)
	if _, err := auth.AdminPrincipal(
		t.Context(),
		protected,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("password-only browser acquired admin access")
	}
	factor := httptest.NewRequest(
		http.MethodPost,
		"/factor",
		strings.NewReader(`{"method":"totp","code":"123456"}`),
	)
	factor.Header.Set("Origin", "https://home.example.test")
	factor.AddCookie(preauth)
	completed := httptest.NewRecorder()
	auth.Handler().ServeHTTP(completed, factor)
	if completed.Code != http.StatusNoContent {
		t.Fatalf("factor status%d %s", completed.Code, completed.Body.String())
	}
	for _, cookie := range completed.Result().Cookies() {
		protected.AddCookie(cookie)
	}
	principal, err := auth.AdminPrincipal(t.Context(), protected)
	if err != nil || principal.AccountID != identity.OwnerAccountID || principal.Method != "totp" {
		t.Fatalf("factor did not establish personal session: %+v %v", principal, err)
	}
	replayRequest := httptest.NewRequest(
		http.MethodPost,
		"/factor",
		strings.NewReader(`{"method":"totp","code":"123456"}`),
	)
	replayRequest.Header.Set("Origin", "https://home.example.test")
	replayRequest.AddCookie(preauth)
	replay := httptest.NewRecorder()
	auth.Handler().ServeHTTP(replay, replayRequest)
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("factor replay admitted: %d", replay.Code)
	}
}

func TestOwnerPasswordHTTPRequiresMigrationAndCSRF(t *testing.T) {
	auth, _, sessions := personalAuthFixture(t, false)

	issued, err := sessions.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
			Method:    "passkey",
			TTL:       5 * time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	csrf, err := auth.csrfCookie(issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	for _, withCSRF := range []bool{false, true} {
		request := httptest.NewRequest(
			http.MethodPost,
			"/owner/password",
			strings.NewReader(`{"email":"owner@example.test","password":"private long password"}`),
		)
		request.Header.Set("Origin", "https://home.example.test")
		request.AddCookie(auth.sessionCookie(issued))
		if withCSRF {
			request.AddCookie(csrf)
			request.Header.Set(csrfHeaderName, csrf.Value)
		}

		response := httptest.NewRecorder()

		auth.Handler().ServeHTTP(response, request)
		if !withCSRF {
			if response.Code != http.StatusForbidden {
				t.Fatalf("setup lacked CSRF: %d", response.Code)
			}

			continue
		}

		if response.Code != http.StatusNoContent {
			t.Fatalf("setup failed: %d %s", response.Code, response.Body.String())
		}

		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == sessionCookieName && cookie.MaxAge >= 0 {
				t.Fatal("owner setup silently granted admin")
			}
		}
	}

	if _, err := sessions.ValidateSession(
		t.Context(),
		issued.Token,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("migration survived password activation")
	}
}

func TestFreshBootstrapRequiresLoopbackOrExplicitSetup(t *testing.T) {
	for _, tc := range []struct {
		peer, forwarded string
		allow           bool
		want            int
	}{
		{"192.0.2.4:1000", "", false, 403}, {"192.0.2.4:1000", "127.0.0.1", false, 403}, {"127.0.0.1:1000", "", false, 200}, {"[::1]:1000", "", false, 200}, {"192.0.2.4:1000", "", true, 200},
	} {
		t.Run(tc.peer+tc.forwarded+http.StatusText(tc.want), func(t *testing.T) {
			auth, err := NewBrowserAuth(
				BrowserAuthConfig{
					Origin:           "https://home.example.test",
					SigningKey:       []byte(strings.Repeat("k", 32)),
					SessionTTL:       time.Hour,
					AllowRemoteSetup: tc.allow,
				},
				verifiedLegacyPasskey{},
				&entropySessions{},
			)
			if err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodPost, "/bootstrap/begin", nil)
			request.RemoteAddr = tc.peer
			request.Header.Set("Origin", "https://home.example.test")
			request.Header.Set("X-Forwarded-For", tc.forwarded)
			response := httptest.NewRecorder()

			auth.Handler().ServeHTTP(response, request)

			if response.Code != tc.want {
				t.Fatalf("setup admission=%d want%d", response.Code, tc.want)
			}
		})
	}
}

func TestConfiguredOwnerLoginPageStartsWithPassword(t *testing.T) {
	auth, _, _ := personalAuthFixture(t, true)
	response := httptest.NewRecorder()

	auth.LoginHandler().
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/login", nil))

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `id="password-login"`) ||
		strings.Contains(response.Body.String(), `id="passkey"`) ||
		strings.Contains(response.Body.String(), `id="bootstrap"`) {
		t.Fatalf(
			"configured owner offered standalone key/bootstrap: %d %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestOwnerSetupPageRequiresValidatedMigration(t *testing.T) {
	auth, _, sessions := personalAuthFixture(t, false)

	issued, err := sessions.CreateSession(
		t.Context(),
		identity.SessionRequest{
			AccountID: identity.OwnerAccountID,
			Purpose:   identity.SessionMigration,
			Method:    "passkey",
			TTL:       5 * time.Minute,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	csrf, err := auth.csrfCookie(issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/admin/login", nil)

	request.AddCookie(auth.sessionCookie(issued))
	request.AddCookie(csrf)
	response := httptest.NewRecorder()

	auth.LoginHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `id="owner-password"`) ||
		!strings.Contains(response.Body.String(), csrf.Value) {
		t.Fatalf(
			"owner proof did not reach scoped setup: %d %s",
			response.Code,
			response.Body.String(),
		)
	}
}

func TestFreshSetupPageDoesNotExposeBootstrapRemotely(t *testing.T) {
	auth, _, _ := personalAuthFixture(t, false)
	response := httptest.NewRecorder()

	auth.LoginHandler().
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/login", nil))

	if response.Code != http.StatusForbidden ||
		strings.Contains(response.Body.String(), `id="bootstrap"`) {
		t.Fatalf("remote page exposed fresh setup: %d", response.Code)
	}
}
