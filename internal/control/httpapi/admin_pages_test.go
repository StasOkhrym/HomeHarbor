package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
	memorypolicy "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
	memoryroutes "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
	memoryservices "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func TestAdminSectionsHaveAuthenticatedNavigation(t *testing.T) {
	deviceService := devices.NewService(memorydevices.NewRepository(), time.Now, nil)
	catalog := controlservices.NewService(memoryservices.NewRepository(), time.Now)
	deps := Dependencies{
		Resources: ResourceDependencies{
			Services: catalog,
			Routes:   controlroutes.NewService(memoryroutes.NewRepository(), time.Now),
			Policy:   policy.NewService(memorypolicy.NewRepository(), acl.Compiler{}),
		},
	}
	for _, path := range []string{"setup", "devices", "services", "access", "network", "invites", "security"} {
		t.Run(path, func(t *testing.T) {
			handler := newTestServer(deviceService, headerAuthorizer{}, deps).Handler()
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/admin/"+path, nil)

			handler.ServeHTTP(response, request)

			if response.Code == http.StatusOK {
				t.Fatal("section allowed an unauthenticated browser")
			}

			response = httptest.NewRecorder()
			request.Header.Set("X-Test-Admin", "true")
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("section status=%d body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `aria-current="page"`) ||
				response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing active navigation or no-store")
			}
		})
	}
}

type failingCatalog struct{ ServiceCatalog }

func (failingCatalog) List(context.Context) ([]controlservices.Service, error) {
	return nil, errors.New("SQL password must not leak")
}

func TestAdminOverviewPreservesPartialFailure(t *testing.T) {
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{
				Services: failingCatalog{
					controlservices.NewService(memoryservices.NewRepository(), time.Now),
				},
			},
		},
	).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	body := response.Body.String()

	if response.Code != http.StatusOK || !strings.Contains(body, "Services could not be loaded") {
		t.Fatalf("partial failure hidden: status=%d body=%s", response.Code, body)
	}
	if strings.Contains(body, "SQL password") ||
		strings.Contains(body, "No services in the catalog") {
		t.Fatal("service failure exposed internals or masqueraded as empty")
	}
	if !strings.Contains(body, "Gateway application unknown") {
		t.Fatal("overview must not imply a successful tunnel")
	}
}

func TestAdminMissingModuleDisablesMutation(t *testing.T) {
	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{},
	).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/network", nil))

	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), `action="/admin/routes"`) {
		t.Fatalf("missing network capability exposed an action: status=%d", response.Code)
	}
}

func TestBrowserExpiredSessionRedirectsWithoutChangingAPI(t *testing.T) {
	handler := mustTestServer(nil, headerAuthorizer{}, Dependencies{}).Handler()
	for _, item := range []struct {
		path   string
		status int
	}{
		{"/admin/devices", http.StatusSeeOther},
		{"/api/v1/admin/devices", http.StatusUnauthorized},
	} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, item.path, nil))

		if response.Code != item.status {
			t.Fatalf("%s status=%d want=%d", item.path, response.Code, item.status)
		}
	}
}

func TestAdminHTMXIsSelfHosted(t *testing.T) {
	response := httptest.NewRecorder()

	mustTestServer(nil, nil, Dependencies{}).Handler().ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/assets/htmx-2.0.11.min.js", nil))

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("HTMX asset status=%d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "2.0.11") {
		t.Fatal("asset is not the pinned upstream library")
	}
}

func TestActivityScriptIsSelfHosted(t *testing.T) {
	response := httptest.NewRecorder()

	mustTestServer(nil, nil, Dependencies{}).Handler().ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/assets/activity.js", nil))

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Header().Get("Content-Type"), "javascript") ||
		!strings.Contains(response.Body.String(), "class ActivityPoller") {
		t.Fatalf("activity asset status=%d", response.Code)
	}
}

func TestAdminActivityUsesReadableActions(t *testing.T) {
	reader := &auditReaderStub{
		events: []audit.Event{{Action: "device.revoked", OccurredAt: time.Now()}},
	}

	handler := newTestServer(
		devices.NewService(memorydevices.NewRepository(), time.Now, nil),
		allowAuthorizer{}, Dependencies{Resources: ResourceDependencies{Audit: reader}},
	).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/admin/activity?limit=999", nil),
	)

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "Device credentials revoked") ||
		reader.limit != maxAuditLimit {
		t.Fatalf("activity status=%d limit=%d", response.Code, reader.limit)
	}
}

type activityDeviceSpy struct {
	DeviceService
	listCalls int
}

func (spy *activityDeviceSpy) List(context.Context) ([]devices.Device, error) {
	spy.listCalls++
	return nil, errors.New("activity must not query devices")
}

func TestActivityDoesNotQueryDevices(t *testing.T) {
	devicesSpy := &activityDeviceSpy{}
	reader := &auditReaderStub{
		events: []audit.Event{{Action: "admin.login", OccurredAt: time.Now()}},
	}

	handler := newTestServer(devicesSpy, allowAuthorizer{}, Dependencies{
		Resources: ResourceDependencies{Audit: reader},
	}).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))

	if response.Code != http.StatusOK || devicesSpy.listCalls != 0 {
		t.Fatalf("activity status=%d device list calls=%d", response.Code, devicesSpy.listCalls)
	}
}

type pageDeviceSpy struct {
	DeviceService
	listCalls int
}

func (spy *pageDeviceSpy) List(context.Context) ([]devices.Device, error) {
	spy.listCalls++
	return nil, nil
}

type pageServiceSpy struct {
	ServiceCatalog
	listCalls int
}

func (spy *pageServiceSpy) List(context.Context) ([]controlservices.Service, error) {
	spy.listCalls++
	return nil, nil
}

type pageProfileSpy struct {
	ProfileService
	listCalls int
}

func (spy *pageProfileSpy) List(context.Context) ([]profiles.AccessProfile, error) {
	spy.listCalls++
	return nil, nil
}

type pageRouteSpy struct {
	RouteService
	listCalls int
}

func (spy *pageRouteSpy) List(context.Context) ([]controlroutes.Advertisement, error) {
	spy.listCalls++
	return nil, nil
}

func TestAdminPagesOnlyReadTheirOwnCollections(t *testing.T) {
	for _, tc := range []struct {
		page     string
		devices  int
		services int
		profiles int
		routes   int
	}{
		{"overview", 1, 1, 0, 1},
		{"settings", 0, 0, 0, 0},
		{"setup", 1, 0, 0, 1},
		{"devices", 1, 0, 0, 0},
		{"services", 0, 1, 0, 0},
		{"access", 1, 1, 1, 0},
		{"network", 1, 0, 0, 1},
		{"invites", 1, 0, 0, 0},
		{"activity", 0, 0, 0, 0},
		{"security", 0, 0, 0, 0},
	} {
		t.Run(tc.page, func(t *testing.T) {
			deviceSpy := &pageDeviceSpy{}
			serviceSpy := &pageServiceSpy{}
			profileSpy := &pageProfileSpy{}
			routeSpy := &pageRouteSpy{}

			handler := newTestServer(deviceSpy, allowAuthorizer{}, Dependencies{
				Resources: ResourceDependencies{
					Services: serviceSpy,
					Profiles: profileSpy,
					Routes:   routeSpy,
				},
			}).Handler()
			response := httptest.NewRecorder()
			path := "/admin/" + tc.page
			if tc.page == "overview" {
				path = "/admin/"
			}

			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

			if deviceSpy.listCalls != tc.devices || serviceSpy.listCalls != tc.services ||
				profileSpy.listCalls != tc.profiles || routeSpy.listCalls != tc.routes {
				t.Fatalf(
					"status=%d queries: devices=%d services=%d profiles=%d routes=%d; want %d/%d/%d/%d",
					response.Code,
					deviceSpy.listCalls,
					serviceSpy.listCalls,
					profileSpy.listCalls,
					routeSpy.listCalls,
					tc.devices,
					tc.services,
					tc.profiles,
					tc.routes,
				)
			}
		})
	}
}

func TestAccessProfilesRemainAvailableWhenCatalogIsMissing(t *testing.T) {
	profileSpy := &pageProfileSpy{}

	handler := newTestServer(&pageDeviceSpy{}, allowAuthorizer{}, Dependencies{
		Resources: ResourceDependencies{Profiles: profileSpy},
	}).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/access", nil))

	if response.Code != http.StatusOK || profileSpy.listCalls != 1 ||
		strings.Contains(response.Body.String(), "Access profiles are not configured") {
		t.Fatalf("access status=%d profile queries=%d body=%s",
			response.Code, profileSpy.listCalls, response.Body.String())
	}
}

func TestActivityFragmentRequiresSessionAndNoStore(t *testing.T) {
	reader := &auditReaderStub{
		events: []audit.Event{{Action: "admin.login", OccurredAt: time.Now()}},
	}

	handler := newTestServer(nil, headerAuthorizer{}, Dependencies{
		Resources: ResourceDependencies{Audit: reader},
	}).Handler()
	path := "/admin/activity/fragment?limit=999&action=admin.login&target_id=session-1"
	unauthorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("HX-Request", "true")
	handler.ServeHTTP(unauthorized, request)

	if unauthorized.Code != http.StatusUnauthorized ||
		unauthorized.Header().Get("HX-Redirect") != "/admin/login" {
		t.Fatalf("fragment auth status=%d redirect=%q", unauthorized.Code,
			unauthorized.Header().Get("HX-Redirect"))
	}

	authorized := httptest.NewRecorder()
	request.Header.Set("X-Test-Admin", "true")
	handler.ServeHTTP(authorized, request)

	if authorized.Code != http.StatusOK || authorized.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(authorized.Body.String(), `data-record-id="1"`) ||
		strings.Contains(authorized.Body.String(), "<html") ||
		reader.query.Limit != maxAuditLimit || reader.query.Action != "admin.login" ||
		reader.query.TargetID != "session-1" {
		t.Fatalf("fragment response status=%d query=%+v body=%s", authorized.Code,
			reader.query, authorized.Body.String())
	}
}

func TestActivityQueryValidatesCursorBeforeReading(t *testing.T) {
	reader := &auditReaderStub{}

	handler := newTestServer(nil, allowAuthorizer{}, Dependencies{
		Resources: ResourceDependencies{Audit: reader},
	}).Handler()
	for _, path := range []string{
		"/admin/activity?before_id=0",
		"/admin/activity/fragment?before_id=-4",
		"/admin/activity/fragment?before_id=bogus",
	} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		if response.Code != http.StatusBadRequest || reader.query.Limit != 0 {
			t.Fatalf("%s status=%d query=%+v", path, response.Code, reader.query)
		}
	}

	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/admin/activity?before_id=42&action=invite.approved", nil,
	))

	if response.Code != http.StatusOK || reader.query.BeforeID != 42 ||
		reader.query.Action != "invite.approved" || reader.query.Limit != audit.DefaultQueryLimit {
		t.Fatalf("history status=%d query=%+v", response.Code, reader.query)
	}
}

func TestActivityRendersOnlyApprovedMetadata(t *testing.T) {
	reader := &auditReaderStub{events: []audit.Event{{
		Action: "invite.approved", OccurredAt: time.Now(),
		ActorType: "unknown", TargetType: "invite", TargetID: "invite-1",
		Metadata: map[string]any{
			"outcome": "success", "correlation_id": "request-1",
			"aggregate_revision": float64(3), "secret": "DO-NOT-RENDER",
		},
	}}}

	handler := newTestServer(nil, allowAuthorizer{}, Dependencies{
		Resources: ResourceDependencies{Audit: reader},
	}).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/activity", nil))
	body := response.Body.String()

	if response.Code != http.StatusOK || !strings.Contains(body, "Invite approved") ||
		!strings.Contains(body, "Succeeded") || !strings.Contains(body, "request-1") ||
		!strings.Contains(body, "Unknown actor") || !strings.Contains(body, "Aggregate revision") ||
		strings.Contains(body, "DO-NOT-RENDER") {
		t.Fatalf("activity status=%d body=%s", response.Code, body)
	}
}
