package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	app, err := NewServer(explicitTestDependencies())
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/services", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing optional services: status=%d", response.Code)
	}
}
