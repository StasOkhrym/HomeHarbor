package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

func TestAuditAPIUsesFacetsAndSafeProjection(t *testing.T) {
	reader := &auditReaderStub{
		events: []audit.Event{
			{
				ActorType: "admin",
				ActorID:   "a-1",
				Action:    "device.revoked",
				Metadata: map[string]any{
					"success":       true,
					"actor_name":    "Olena",
					"authorization": "SECRET_TOKEN",
				},
			},
		},
	}

	handler := newTestServer(
		nil,
		allowAuthorizer{},
		Dependencies{Resources: ResourceDependencies{Audit: reader}},
	).Handler()
	response := httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodGet,
			"/api/v1/admin/audit?category=devices&outcome=success&device_id=d-1&actor_id=a-1&period=24h&before_id=100",
			nil,
		),
	)

	if response.Code != 200 || reader.query.Category != "devices" ||
		reader.query.DeviceID != "d-1" ||
		reader.query.ActorID != "a-1" ||
		reader.query.Outcome != "success" ||
		reader.query.BeforeID != 100 ||
		reader.query.Since.IsZero() ||
		reader.query.Until.IsZero() ||
		strings.Contains(response.Body.String(), "SECRET") ||
		!strings.Contains(response.Body.String(), "Olena") {
		t.Fatalf(
			"audit status=%d query=%+v body=%s",
			response.Code,
			reader.query,
			response.Body.String(),
		)
	}

	response = httptest.NewRecorder()

	handler.ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/api/v1/admin/audit?category=invalid", nil),
	)

	if response.Code != 400 {
		t.Fatalf("invalid filter broadened: %d", response.Code)
	}
}
