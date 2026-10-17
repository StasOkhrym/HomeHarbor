package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	webadmin "github.com/StasOkhrym/homeharbor/internal/web/admin"
)

func explicitTestDependencies() Dependencies {
	return Dependencies{
		Security: SecurityDependencies{
			Authorizer:    allowAuthorizer{},
			APILimiter:    NewRateLimiter(120, time.Minute, nil),
			AuthLimiter:   NewRateLimiter(5, time.Minute, nil),
			DeviceLimiter: NewRateLimiter(10, time.Minute, nil),
		},
	}
}

func TestNewServerRejectsIncompleteBrowserDependencies(t *testing.T) {
	deps := explicitTestDependencies()

	deps.Browser.API = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("incomplete browser authentication was accepted")
	}
}

func TestNewServerRejectsBrowserAuthWithoutAdminHandler(t *testing.T) {
	deps := explicitTestDependencies()

	noop := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	deps.Browser = BrowserDependencies{
		API: noop, LoginPage: noop, LoginAsset: noop,
		MutationAuthorizer: func(context.Context, *http.Request) (bool, error) {
			return true, nil
		},
	}

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("browser authentication was accepted without its protected admin handler")
	}
}

func TestNewServerRejectsRelayWithoutPeerAuthorization(t *testing.T) {
	deps := explicitTestDependencies()
	deps.Relay.URL = "wss://relay.localhost/relay"

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("incomplete authenticated relay issuance was accepted")
	}
}

func TestNewServerRejectsIncompleteActivationHandlers(t *testing.T) {
	deps := explicitTestDependencies()
	deps.Activation.Challenge = func(http.ResponseWriter, *http.Request) {}

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("activation was enabled without its possession claim handler")
	}
}

func TestNewServerRequiresExplicitSecurityStores(t *testing.T) {
	deps := explicitTestDependencies()
	deps.Security.AuthLimiter = nil

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("missing security authority silently selected a memory fallback")
	}
}

func TestNewServerAllowsUnavailableOptionalResources(t *testing.T) {
	deps := explicitTestDependencies()

	deps.Browser.Admin = webadmin.NewHandler(webadmin.Dependencies{}).Routes()

	app, err := NewServer(deps)
	if err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()

	app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/services", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing optional services: status=%d", response.Code)
	}
}

func TestNewServerRejectsAccountAPIWithoutBrowserSecurity(t *testing.T) {
	deps := explicitTestDependencies()

	deps.Browser.AccountAPI = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	if app, err := NewServer(deps); err == nil || app != nil {
		t.Fatal("account management accepted without its browser security boundary")
	}
}
