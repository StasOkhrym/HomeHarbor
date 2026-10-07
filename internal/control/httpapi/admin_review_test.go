package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
)

func TestRecoveryFormCannotSubmitSecretsInURL(t *testing.T) {
	response := httptest.NewRecorder()
	if err := loginTemplate.Execute(response, loginPageModel{}); err != nil {
		t.Fatal(err)
	}
	body := response.Body.String()
	form := regexp.MustCompile(`<form\s+[^>]*id="recovery"[^>]*>`).FindString(body)
	if !strings.Contains(form, `method="post"`) ||
		!strings.Contains(form, `action="/admin/login"`) {
		t.Fatalf("recovery needs a safe non-GET fallback: %s", form)
	}
	if !regexp.MustCompile(`<fieldset\s+[^>]*disabled`).MatchString(body) {
		t.Fatal("recovery must remain disabled before the handler is installed")
	}
}

func TestProfileCheckboxIDsAreOpaque(t *testing.T) {
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now)
	for _, id := range []string{"photos,admin", "photos", "admin"} {
		if _, err := catalog.Create(context.Background(), controlservices.Service{
			ID: id, Name: id, Kind: controlservices.KindWeb, URL: "https://photos.home.arpa",
		}); err != nil {
			t.Fatal(err)
		}
	}
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{Resources: ResourceDependencies{Services: catalog}},
	).Handler()
	response := postAdminForm(handler, "/admin/access-profiles", url.Values{
		"name": {"Family"}, "service_ids": {"photos,admin"},
	})
	profiles, err := catalog.Profiles(context.Background())
	if response.Code != http.StatusSeeOther || err != nil || len(profiles) != 1 {
		t.Fatalf("profile creation: status=%d profiles=%v err=%v", response.Code, profiles, err)
	}
	if ids := profiles[0].ServiceIDs; len(ids) != 1 || ids[0] != "photos,admin" {
		t.Fatalf("checkbox selection changed memberships: %v", ids)
	}
}

func TestRouteActionPreservesExactRecordID(t *testing.T) {
	routes := controlroutes.NewService(controlroutes.NewMemoryStore(), time.Now)
	for _, id := range []string{"a/../b", "b"} {
		if _, err := routes.Advertise(context.Background(), controlroutes.AdvertisementRequest{
			ID: id, GatewayDeviceID: "gateway", Prefix: netip.MustParsePrefix("192.168.50.0/24"),
			Resolver: netip.MustParseAddr("192.168.50.1"), DomainSuffix: "home.arpa",
		}); err != nil {
			t.Fatal(err)
		}
	}
	handler := newTestServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Routes: routes}}).Handler()
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/admin/network", nil))
	if strings.Contains(page.Body.String(), `/admin/routes/a/../b/`) {
		t.Fatal("route ID entered a browser-normalized action path")
	}
	response := postAdminForm(handler, "/admin/routes/approve", url.Values{"route_id": {"a/../b"}})
	if response.Code != http.StatusSeeOther {
		t.Fatalf("exact-ID approval status=%d", response.Code)
	}
	items, _ := routes.List(context.Background())
	for _, item := range items {
		want := controlroutes.StatusPending
		if item.ID == "a/../b" {
			want = controlroutes.StatusApproved
		}
		if item.Status != want {
			t.Errorf("route %q: got %s want %s", item.ID, item.Status, want)
		}
	}
}

func TestMalformedURLNeverRetainsCredentials(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{
				Services: controlservices.NewService(controlservices.NewMemoryStore(), time.Now),
			},
		},
	).Handler()
	response := postAdminForm(handler, "/admin/services", url.Values{
		"name": {
			"Photos",
		},
		"kind": {"web"},
		"url":  {"https://user:secret-review-password@example.com/%zz"},
	})
	if response.Code != http.StatusBadRequest ||
		strings.Contains(response.Body.String(), "secret-review-password") {
		t.Fatal("malformed URL echoed credentials")
	}
}

func TestPolicyErrorKeepsUnrelatedProfileID(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{
				Services: controlservices.NewService(controlservices.NewMemoryStore(), time.Now),
				Policy:   policy.NewService(policy.NewMemoryStore(), acl.Compiler{}),
			},
		},
	).Handler()
	response := postAdminForm(handler, "/admin/policy/preview", url.Values{"rules": {"not JSON"}})
	if response.Code != http.StatusBadRequest || htmlInput(t, response.Body.String(), "id") == "" {
		t.Fatal("ACL validation discarded the profile form ID")
	}
}
