package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSettingsRoutePreservesAuthenticationAndLegacyDestinations(t *testing.T) {
	handler := mustTestServer(nil, headerAuthorizer{}, Dependencies{}).Handler()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/admin/settings", nil)

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("settings authentication status=%d", response.Code)
	}

	response = httptest.NewRecorder()
	request.Header.Set("X-Test-Admin", "true")
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("settings status=%d", response.Code)
	}

	for _, path := range []string{"/admin/access", "/admin/network", "/admin/security", "/admin/setup"} {
		if !strings.Contains(response.Body.String(), `href="`+path+`"`) {
			t.Fatalf("legacy destination missing: %s", path)
		}
	}
}
