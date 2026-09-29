package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func TestRouterAddsRequestID(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID is empty")
	}
}

func TestRouterPreservesIncomingRequestID(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Header.Set("X-Request-ID", "external-request-id")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got != "external-request-id" {
		t.Fatalf("request ID = %q", got)
	}
}

func TestRouterRejectsOversizedAPIBody(t *testing.T) {
	handler := NewServer(devices.NewService(devices.NewMemoryStore(), time.Now, nil), allowAuthorizer{}).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBufferString(`{"padding":"`+strings.Repeat("x", int(maxRequestBodyBytes)+1)+`"}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", response.Code)
	}
}
