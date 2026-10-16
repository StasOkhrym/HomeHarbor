package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type connectionDeviceList struct{ DeviceService }

func (connectionDeviceList) List(context.Context) ([]devices.Device, error) {
	return []devices.Device{{ID: "phone", Name: "Olena phone", Status: devices.StatusActive}}, nil
}

type connectionTelemetryReader struct{ calls int }

func (r *connectionTelemetryReader) Latest(context.Context, int) ([]telemetry.Observation, error) {
	r.calls++
	return []telemetry.Observation{
		{
			ReporterDeviceID: "phone",
			SubjectDeviceID:  "phone",
			State:            protocol.RuntimeRunning,
			ObservedAt:       time.Now(),
			Sample:           protocol.PeerObservation{DeviceID: "phone"},
		},
	}, nil
}

func TestConnectionsRoutesAreProtectedAndSeparateFromActivity(t *testing.T) {
	reader := &connectionTelemetryReader{}

	handler := newTestServer(
		connectionDeviceList{},
		headerAuthorizer{},
		Dependencies{Resources: ResourceDependencies{Telemetry: reader}},
	).Handler()
	for _, path := range []string{"/admin/connections", "/admin/connections/fragment", "/api/v1/admin/connections"} {
		before := reader.calls
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("HX-Request", "true")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusUnauthorized || reader.calls != before {
			t.Fatalf("unprotected %s status=%d reads=%d", path, response.Code, reader.calls)
		}

		request = httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Test-Admin", "true")
		response = httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		if strings.HasPrefix(path, "/admin/") &&
			(!strings.Contains(response.Body.String(), "Olena phone") || !strings.Contains(response.Body.String(), "Runtime running")) {
			t.Fatalf("missing runtime page %s: %s", path, response.Body.String())
		}
		if strings.HasSuffix(path, "/fragment") &&
			strings.Contains(response.Body.String(), "<html") {
			t.Fatal("fragment included full document")
		}
	}

	before := reader.calls
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/admin/activity", nil)
	request.Header.Set("X-Test-Admin", "true")
	handler.ServeHTTP(response, request)

	if reader.calls != before {
		t.Fatal("historical activity queried live telemetry")
	}
}

func TestConnectionPollingAssetsAreSelfHosted(t *testing.T) {
	handler := newTestServer(nil, allowAuthorizer{}, Dependencies{}).Handler()
	for _, path := range []string{"/assets/live-poll.js", "/assets/connections.js"} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))

		if response.Code != 200 ||
			!strings.Contains(response.Header().Get("Content-Type"), "javascript") ||
			!strings.Contains(response.Body.String(), "HomeHarborLivePoller") {
			t.Fatalf("missing polling asset %s status=%d", path, response.Code)
		}
	}
}
