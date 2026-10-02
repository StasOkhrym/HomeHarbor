package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestLoginPageSelectsSetupState(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "first run", true: "registered"}[registered],
			func(t *testing.T) {
				auth, _ := newBrowserAuthTest(t)
				store := identity.NewMemoryStore()
				if registered {
					if err := store.SaveCredential(
						context.Background(),
						[]byte("admin"),
						webauthn.Credential{ID: []byte("key")},
					); err != nil {
						t.Fatal(err)
					}
				}
				auth.setupState = store
				response := httptest.NewRecorder()
				auth.LoginHandler().
					ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
				body := response.Body.String()
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", response.Code, body)
				}
				if strings.Contains(body, `id="bootstrap"`) == registered {
					t.Fatal("bootstrap control does not match credential state")
				}
				if strings.Contains(body, `id="passkey"`) != registered {
					t.Fatal("login control does not match credential state")
				}
				if !strings.Contains(body, "/assets/admin.css") ||
					response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("login must use local styling and must not be cached")
				}
			},
		)
	}
}

type unavailableSetupState struct{}

func (unavailableSetupState) HasCredentials(context.Context) (bool, error) {
	return false, errors.New("database password must never be shown")
}

func TestLoginStateFailureDoesNotExposeBootstrap(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)
	auth.setupState = unavailableSetupState{}
	response := httptest.NewRecorder()
	auth.LoginHandler().
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup failure status=%d", response.Code)
	}
	if body := response.Body.String(); strings.Contains(body, `id="bootstrap"`) ||
		strings.Contains(body, "database password") {
		t.Fatal("failed lookup exposed bootstrap or internal details")
	}
}
