package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
)

func TestAdminMutationsShareBrowserSecurityBoundary(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		auth,
		Dependencies{
			Resources: ResourceDependencies{
				Policy:   policy.NewService(policy.NewMemoryStore(), policy.Compiler{}),
				Services: controlservices.NewService(controlservices.NewMemoryStore(), time.Now),
			},
			Browser: BrowserDependencies{
				API:                auth.Handler(),
				LoginPage:          auth.LoginHandler(),
				LoginAsset:         auth.LoginAssetHandler(),
				MutationAuthorizer: auth.AuthorizeMutation,
				ActionConfirmation: auth,
			},
		},
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
						request.AddCookie(auth.sessionCookie(sessions.session))
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

func TestAdminCredentialRevokeRequiresDeviceScopedProof(t *testing.T) {
	store := devices.NewMemoryStore()
	service := devices.NewService(store, time.Now, nil)
	// Persist a registered identity using the real repository fixture API.
	for _, id := range []string{"device-a", "device-b"} {
		if err := store.SaveDevice(
			context.Background(),
			devices.Device{
				ID:                 id,
				Name:               id,
				Role:               devices.RoleClient,
				Status:             devices.StatusActive,
				CreatedAt:          time.Now(),
				IdentityPublicKey:  id + "-identity",
				WireGuardPublicKey: id + "-wg",
			},
		); err != nil {
			t.Fatal(err)
		}
	}
	auth, _ := newBrowserAuthTest(t)
	handler := newTestServer(
		service,
		allowAuthorizer{}, Dependencies{Browser: BrowserDependencies{ActionConfirmation: auth}},
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
	).Code; got != http.StatusBadRequest {
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
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{
				Policy: policy.NewService(policy.NewMemoryStore(), policy.Compiler{}),
			},
			Browser: BrowserDependencies{ActionConfirmation: auth},
		},
	).Handler()
	response := postAdminForm(handler, "/admin/policy/preview", url.Values{"rules": {"null"}})
	if response.Code != http.StatusBadRequest {
		t.Fatal("null must not silently clear every allow rule")
	}
}

func TestAdminPolicyJSONEmptyIsArray(t *testing.T) {
	model := adminPageModel{Values: url.Values{}}
	server := mustTestServer(
		nil,
		nil,
		Dependencies{
			Resources: ResourceDependencies{
				Policy: policy.NewService(policy.NewMemoryStore(), policy.Compiler{}),
			},
		},
	)
	server.loadAdminPolicy(context.Background(), &model)
	var value any
	if err := json.Unmarshal([]byte(model.PolicyJSON), &value); err != nil {
		t.Fatal(err)
	}
	if _, ok := value.([]any); !ok {
		t.Fatalf("empty editor=%s", model.PolicyJSON)
	}
}

func TestBrowserMutationRejectsForeignOriginWithValidCSRF(t *testing.T) {
	auth, sessions := newBrowserAuthTest(t)
	csrf, err := auth.csrfCookie(sessions.session.Token, sessions.session.ExpiresAt)
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
	request.AddCookie(auth.sessionCookie(sessions.session))
	request.AddCookie(csrf)
	allowed, err := auth.AuthorizeMutation(context.Background(), request)
	if err != nil || allowed {
		t.Fatal("valid CSRF allowed a foreign-origin browser mutation")
	}
}
