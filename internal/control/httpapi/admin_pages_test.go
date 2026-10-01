package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
)

func TestAdminSectionsHaveAuthenticatedNavigation(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	catalog := controlservices.NewService(controlservices.NewMemoryStore(), time.Now)
	options := []ServerOption{
		WithServiceCatalog(catalog),
		WithRouteService(controlroutes.NewService(controlroutes.NewMemoryStore(), time.Now)),
		WithPolicyService(policy.NewService(policy.NewMemoryStore(), policy.Compiler{})),
	}
	for _, path := range []string{"setup", "devices", "services", "access", "network", "invites", "security"} {
		t.Run(path, func(t *testing.T) {
			handler := newTestServer(deviceService, headerAuthorizer{}, options...).Handler()
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
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		WithServiceCatalog(
			failingCatalog{controlservices.NewService(controlservices.NewMemoryStore(), time.Now)},
		),
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
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
	).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/network", nil))
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), `action="/admin/routes"`) {
		t.Fatalf("missing network capability exposed an action: status=%d", response.Code)
	}
}

func TestBrowserExpiredSessionRedirectsWithoutChangingAPI(t *testing.T) {
	handler := NewServer(nil, headerAuthorizer{}).Handler()
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
	NewServer(nil, nil).Handler().ServeHTTP(response,
		httptest.NewRequest(http.MethodGet, "/assets/htmx-2.0.11.min.js", nil))
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("HTMX asset status=%d", response.Code)
	}
	if !strings.Contains(response.Body.String(), "2.0.11") {
		t.Fatal("asset is not the pinned upstream library")
	}
}

func TestAdminActivityUsesReadableActions(t *testing.T) {
	reader := &auditReaderStub{
		events: []audit.Event{{Action: "device.revoked", OccurredAt: time.Now()}},
	}
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
		WithAuditReader(reader),
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
