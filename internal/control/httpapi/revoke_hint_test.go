package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

func TestSuccessfulRevokeInvalidatesLocalSession(t *testing.T) {
	service := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	token, err := service.IssueEnrollmentToken(context.Background(), devices.RoleClient, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	device, err := service.Enroll(
		context.Background(),
		validEnrollmentRequest(t, token.Token, "client"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var invalidated string
	server := newTestServer(
		service,
		headerAuthorizer{},
		Dependencies{
			Resources: ResourceDependencies{InvalidateDevice: func(id string) { invalidated = id }},
		},
	)
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.SetPathValue("id", device.ID)
	response := httptest.NewRecorder()
	server.revokeDevice(response, request)
	if response.Code != http.StatusNoContent || invalidated != device.ID {
		t.Fatalf("status=%d hint=%q", response.Code, invalidated)
	}
}
