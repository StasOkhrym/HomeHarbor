package httpapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

func TestRouterAddsRequestID(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
	).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID is empty")
	}
}

func TestRouterPreservesIncomingRequestID(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
	).Handler()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Header.Set("X-Request-ID", "external-request-id")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got != "external-request-id" {
		t.Fatalf("request ID = %q", got)
	}
}

func TestRouterReplacesUnsafeRequestID(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
	).Handler()
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	request.Header.Set("X-Request-ID", "request\nwith-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got == "request\nwith-secret" || got == "" {
		t.Fatalf("unsafe request ID was retained: %q", got)
	}
}

func TestRouterRejectsOversizedAPIBody(t *testing.T) {
	handler := newTestServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		allowAuthorizer{},
	).Handler()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/enroll",
		bytes.NewBufferString(`{"padding":"`+strings.Repeat("x", int(maxRequestBodyBytes)+1)+`"}`),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestRecoverMiddlewareReturnsStableInternalError(t *testing.T) {
	handler := recoverMiddleware(
		slog.Default(),
	)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("database password=secret")
		}),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "database password") ||
		strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("panic details leaked in response: %s", response.Body.String())
	}
}

type readOnlyAuthorizer struct{}

func (readOnlyAuthorizer) IsAdmin(context.Context, *http.Request) (bool, error) { return true, nil }

func TestAdminMutationRequiresExplicitMutationAuthorization(t *testing.T) {
	server := NewServer(
		devices.NewService(devices.NewMemoryStore(), time.Now, nil),
		readOnlyAuthorizer{},
	)
	response := httptest.NewRecorder()
	server.Handler().
		ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrollment-tokens", strings.NewReader(`{"role":"client","ttl_seconds":60}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("mutation status=%d", response.Code)
	}
}
