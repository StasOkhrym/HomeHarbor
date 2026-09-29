package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func TestEnrollmentAPIRequiresAdminAndEnrollsDevice(t *testing.T) {
	deviceService := devices.NewService(devices.NewMemoryStore(), time.Now, nil)
	handler := NewServer(deviceService, headerAuthorizer{}).Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", bytes.NewBufferString(`{"role":"client","ttl_seconds":3600}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	issueRequest := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", bytes.NewBufferString(`{"role":"client","ttl_seconds":3600}`))
	issueRequest.Header.Set("X-Test-Admin", "true")
	issued := httptest.NewRecorder()
	handler.ServeHTTP(issued, issueRequest)
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue status = %d body=%s", issued.Code, issued.Body.String())
	}
	var token devices.IssuedToken
	if err := json.NewDecoder(issued.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(devices.EnrollRequest{Token: token.Token, Name: "laptop", IdentityPublicKey: "identity", WireGuardPublicKey: "wireguard"})
	enrolled := httptest.NewRecorder()
	handler.ServeHTTP(enrolled, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body)))
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d body=%s", enrolled.Code, enrolled.Body.String())
	}

	listRequest := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	listRequest.Header.Set("X-Test-Admin", "true")
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, listRequest)
	if listed.Code != http.StatusOK {
		t.Fatalf("list status = %d", listed.Code)
	}
}

func TestHealthEndpoints(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, recorder.Code)
		}
	}
}

type allowAuthorizer struct{}

func (allowAuthorizer) IsAdmin(context.Context, *http.Request) bool { return true }

type headerAuthorizer struct{}

func (headerAuthorizer) IsAdmin(_ context.Context, request *http.Request) bool {
	return request.Header.Get("X-Test-Admin") == "true"
}
