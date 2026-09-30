package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestActivationRoutesUseExplicitHandlers(t *testing.T) {
	for _, action := range []string{"challenge", "claim"} {
		t.Run(action, func(t *testing.T) {
			called := false
			handler := func(w http.ResponseWriter, r *http.Request) {
				called = chi.URLParam(r, "id") == "invite-1"
				w.WriteHeader(http.StatusNoContent)
			}
			server := NewServer(nil, nil, WithActivationHandlers(handler, handler))
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/invites/invite-1/"+action, nil))
			if response.Code != http.StatusNoContent || !called {
				t.Fatalf("explicit route missing: status=%d called=%v", response.Code, called)
			}
		})
	}
}
