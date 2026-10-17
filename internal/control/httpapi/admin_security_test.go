package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
	memorypolicy "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
	memoryservices "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func TestAdminMutationsShareBrowserSecurityBoundary(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		auth,
		Dependencies{
			Resources: ResourceDependencies{
				Policy:   policy.NewService(memorypolicy.NewRepository(), acl.Compiler{}),
				Services: controlservices.NewService(memoryservices.NewRepository(), time.Now),
			},
			Browser: BrowserDependencies{
				API:                auth.Handler(),
				LoginPage:          auth.LoginHandler(),
				LoginAsset:         auth.LoginAssetHandler(),
				MutationAuthorizer: auth.AuthorizeMutation,
			},
		},
		auth,
	).Handler()
	for _, path := range []string{"services", "access-profiles", "enrollment-tokens", "policy/preview", "policy", "devices/device-a/revoke"} {
		t.Run(path, func(t *testing.T) {
			for _, scenario := range []string{"anonymous", "no-csrf", "wrong-origin", "expired"} {
				t.Run(scenario, func(t *testing.T) {
					request := httptest.NewRequest(
						http.MethodPost,
						"/admin/"+path,
						strings.NewReader("name=Test"),
					)
					request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					request.Header.Set("Origin", "https://tunnel.example.com")
					status := http.StatusUnauthorized
					if scenario == "anonymous" {
						status = http.StatusUnauthorized
					} else {
						request.AddCookie(browserSessionCookie(t, sessions.session))
					}

					if scenario == "wrong-origin" {
						request.Header.Set("Origin", "https://attacker.example")
					}

					if scenario == "expired" {
						sessions.session.ExpiresAt = time.Now().Add(-time.Minute)
						status = http.StatusUnauthorized
					}

					response := httptest.NewRecorder()

					handler.ServeHTTP(response, request)
					sessions.session.ExpiresAt = time.Now().Add(time.Hour)

					if response.Code != status {
						t.Errorf("status=%d want=%d", response.Code, status)
					}
				})
			}
		})
	}
}

func TestMalformedAdminFormRejectedBeforeMutationAuthorization(t *testing.T) {
	authorizationCalls := 0

	handler := newTestServer(nil, allowAuthorizer{}, Dependencies{
		Browser: BrowserDependencies{
			MutationAuthorizer: func(context.Context, *http.Request) (bool, error) {
				authorizationCalls++
				return true, nil
			},
		},
	}).Handler()
	request := httptest.NewRequest(
		http.MethodPost,
		"/admin/services",
		strings.NewReader("name=%ZZ"),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || authorizationCalls != 0 {
		t.Fatalf("malformed form status=%d authorization calls=%d",
			response.Code, authorizationCalls)
	}
}

func TestAdminCredentialRevokeRequiresDeviceScopedProof(t *testing.T) {
	store := memorydevices.NewRepository()
	service := devices.NewService(store, time.Now, nil)
	// Persist a registered identity using the real repository fixture API.
	for index, id := range []string{"device-a", "device-b"} {
		if err := store.SeedDevice(
			context.Background(),
			devices.Device{
				ID:                 id,
				Name:               id,
				Role:               devices.RoleClient,
				Status:             devices.StatusActive,
				CreatedAt:          time.Now(),
				IdentityPublicKey:  id + "-identity",
				WireGuardPublicKey: id + "-wg",
				CredentialHash:     [32]byte{byte(index + 1)},
			},
		); err != nil {
			t.Fatal(err)
		}
	}

	auth, _ := newBrowserAuthTest(t)

	handler := newTestServer(
		service,
		allowAuthorizer{}, Dependencies{},
		auth,
	).Handler()
	page := httptest.NewRecorder()

	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/admin/devices/device-a", nil))
	proof := htmlInput(t, page.Body.String(), "proof")
	values := url.Values{"confirmed": {"yes"}, "proof": {proof}}
	if got := postAdminForm(
		handler,
		"/admin/devices/device-b/revoke",
		values,
	).Code; got != http.StatusForbidden {
		t.Fatalf("substitution status=%d", got)
	}

	values.Del("confirmed")

	if got := postAdminForm(
		handler,
		"/admin/devices/device-a/revoke",
		values,
	).Code; got != http.StatusUnprocessableEntity {
		t.Fatalf("unconfirmed status=%d", got)
	}

	values.Set("confirmed", "yes")

	if got := postAdminForm(
		handler,
		"/admin/devices/device-a/revoke",
		values,
	).Code; got != http.StatusSeeOther {
		t.Fatalf("confirmed status=%d", got)
	}

	a, _ := store.Device(context.Background(), "device-a")

	b, _ := store.Device(context.Background(), "device-b")

	if a.Status != devices.StatusRevoked || b.Status != devices.StatusActive {
		t.Fatalf("wrong devices revoked: %s/%s", a.Status, b.Status)
	}
}

func TestAdminPolicyPreviewRequiresArray(t *testing.T) {
	auth, _ := newBrowserAuthTest(t)

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{
				Policy: policy.NewService(memorypolicy.NewRepository(), acl.Compiler{}),
			},
		},
		auth,
	).Handler()

	response := postAdminForm(handler, "/admin/policy/preview", url.Values{"rules": {"null"}})

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatal("null must not silently clear every allow rule")
	}
}

func TestBrowserMutationRejectsForeignOriginWithValidCSRF(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)

	csrf, err := browserCSRFCookie(t, sessions.session)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/admin/services",
		strings.NewReader(url.Values{"_csrf": {csrf.Value}}.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://attacker.example")
	request.AddCookie(browserSessionCookie(t, sessions.session))
	request.AddCookie(csrf)

	allowed, err := auth.AuthorizeMutation(context.Background(), request)

	if err != nil || allowed {
		t.Fatal("valid CSRF allowed a foreign-origin browser mutation")
	}
}

func TestAccountAPIIsMountedBehindSessionAndCSRF(t *testing.T) {
	calls := 0

	auth, sessions := newBrowserAuthTest(t)

	handler := newTestServer(nil, auth, Dependencies{Browser: BrowserDependencies{
		API:                auth.Handler(),
		LoginPage:          auth.LoginHandler(),
		LoginAsset:         auth.LoginAssetHandler(),
		MutationAuthorizer: auth.AuthorizeMutation,
		AccountAPI: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++

			if principal, ok := identity.PrincipalFromContext(
				r.Context(),
			); !ok ||
				!principal.CanManageNetwork() {
				t.Error("missing verified principal")
			}

			w.WriteHeader(http.StatusNoContent)
		}),
	}}, auth).Handler()
	for _, tc := range []struct {
		name                  string
		session, csrf, origin bool
		want                  int
	}{
		{"anonymous", false, false, true, http.StatusUnauthorized}, {"missing-csrf", true, false, true, http.StatusUnauthorized}, {"wrong-origin", true, true, false, http.StatusUnauthorized}, {"authorized", true, true, true, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/admin/account/recovery-codes",
				strings.NewReader("{}"),
			)
			if tc.session {
				request.AddCookie(browserSessionCookie(t, sessions.session))
			}

			request.Header.Set("Origin", "https://tunnel.example.com")
			if !tc.origin {
				request.Header.Set("Origin", "https://attacker.example")
			}

			if tc.csrf {
				cookie, err := browserCSRFCookie(t, sessions.session)
				if err != nil {
					t.Fatal(err)
				}

				request.AddCookie(cookie)
				request.Header.Set("X-CSRF-Token", cookie.Value)
			}

			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tc.want {
				t.Fatalf("status %d want %d: %s", response.Code, tc.want, response.Body.String())
			}
		})
	}

	if calls != 1 {
		t.Fatal("account handler called outside security boundary", calls)
	}
}
