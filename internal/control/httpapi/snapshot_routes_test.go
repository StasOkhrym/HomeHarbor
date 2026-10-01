package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSnapshotHistoryHasExplicitHTTPRoute(t *testing.T) {
	called := false
	server := NewServer(
		nil,
		nil,
		WithSnapshotHistoryHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})),
	)
	response := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/coordination/snapshots", nil))
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("missing history route: status=%d called=%v", response.Code, called)
	}
}
