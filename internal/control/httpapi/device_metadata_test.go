package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

type metadataWriter struct {
	id       string
	metadata devices.Metadata
}

func (m *metadataWriter) Report(_ context.Context, id string, value devices.Metadata) error {
	m.id, m.metadata = id, value
	return nil
}

type metadataDeviceAuth struct{ DeviceService }

func (metadataDeviceAuth) Authenticate(context.Context, string) (devices.Device, error) {
	return devices.Device{ID: "own-device", Name: "Old name", Status: devices.StatusActive}, nil
}

func TestDeviceMetadataIsSelfScopedAndRejectsForeignFields(t *testing.T) {
	writer := &metadataWriter{}

	handler := newTestServer(
		metadataDeviceAuth{},
		allowAuthorizer{},
		Dependencies{Resources: ResourceDependencies{DeviceMetadata: writer}},
	).Handler()
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/devices/self/metadata",
		strings.NewReader(
			`{"name":"Kitchen Mac","platform":"macos","os_version":"15.0","client_version":"0.1"}`,
		),
	)
	request.Header.Set("Authorization", "Bearer valid-device-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || writer.id != "own-device" ||
		writer.metadata.Name != "Kitchen Mac" {
		t.Fatalf(
			"metadata status=%d id=%s body=%s",
			response.Code,
			writer.id,
			response.Body.String(),
		)
	}

	writer.id = ""
	request = httptest.NewRequest(
		http.MethodPut,
		"/api/v1/devices/self/metadata",
		strings.NewReader(`{"device_id":"foreign-device","name":"Injected","platform":"ios"}`),
	)
	request.Header.Set("Authorization", "Bearer valid-device-token")
	response = httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || writer.id != "" {
		t.Fatalf("foreign identity accepted status=%d id=%s", response.Code, writer.id)
	}
}
