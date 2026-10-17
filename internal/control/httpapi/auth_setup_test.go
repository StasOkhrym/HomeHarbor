package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	memoryidentity "github.com/StasOkhrym/homeharbor/internal/testutil/control/identity"
	webauth "github.com/StasOkhrym/homeharbor/internal/web/auth"
)

func newSetupAuth(t *testing.T, state webauth.PasskeyState) *webauth.BrowserAuth {
	t.Helper()

	auth, err := webauth.NewBrowserAuth(webauth.BrowserAuthConfig{
		Origin:           "https://tunnel.example.com",
		SigningKey:       []byte(strings.Repeat("k", 32)),
		SessionTTL:       time.Hour,
		SetupState:       state,
		Accounts:         memoryidentity.NewRepository(),
		AllowRemoteSetup: true,
	}, fakePasskeys{}, &fakeSessions{})
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

func TestLoginPageSelectsSetupState(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "first run", true: "registered"}[registered],
			func(t *testing.T) {
				store := memoryidentity.NewRepository()
				if registered {
					if err := store.SaveBootstrapCredential(
						context.Background(),
						[]byte("homeharbor-admin-v1"),
						webauthn.Credential{ID: []byte("key")},
					); err != nil {
						t.Fatal(err)
					}
				}

				auth := newSetupAuth(t, store)
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

type registeredSetupState struct{}

func (registeredSetupState) HasCredentials(context.Context) (bool, error) {
	return true, nil
}

func (unavailableSetupState) HasCredentials(context.Context) (bool, error) {
	return false, errors.New("database password must never be shown")
}

func TestLoginStateFailureDoesNotExposeBootstrap(t *testing.T) {
	auth := newSetupAuth(t, unavailableSetupState{})
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
