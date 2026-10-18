package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type unavailableLimitStore struct{}

func (unavailableLimitStore) Allow(
	context.Context,
	string,
	string,
	int,
	time.Duration,
) (bool, time.Duration, error) {
	return false, 0, errors.New("redis unavailable")
}

func TestSharedLimiterFailsClosedOnStoreFailure(t *testing.T) {
	limiter := NewSharedRateLimiter(unavailableLimitStore{}, "login", 5, time.Minute)
	called := false
	handler := limiter.Middleware(
		func(*http.Request) string { return "client" },
	)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/login", nil))

	if response.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("status=%d handler called=%v", response.Code, called)
	}
}

func TestConfiguredRateLimitsPreserveSharedFailure(t *testing.T) {
	for _, store := range []RateLimitStore{unavailableLimitStore{}, nil} {
		deps := explicitTestDependencies()
		deps.Security.AuthLimiter = NewSharedRateLimiter(store, "auth", 6, time.Minute)
		deps.Security.DeviceLimiter = NewSharedRateLimiter(store, "onboarding", 12, time.Minute)
		deps.Security.AuthLimiter.storeTimeout = 2 * time.Second
		deps.Security.DeviceLimiter.storeTimeout = 2 * time.Second

		s, err := NewServer(deps)
		if store == nil {
			if err == nil {
				t.Fatal("missing shared authority was accepted")
			}

			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		if s.authLimiter.limit != 6 || s.deviceLimiter.limit != 12 {
			t.Fatal("option order reset configured quotas")
		}

		response := httptest.NewRecorder()

		s.authLimiter.Middleware(func(*http.Request) string { return "client" })(
			http.HandlerFunc(
				func(http.ResponseWriter, *http.Request) { t.Fatal("shared failure admitted request") },
			),
		).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/login", nil))

		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", response.Code)
		}
	}
}

func TestRateLimiterRejectsRequestsAfterLimit(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	limiter := NewRateLimiter(2, time.Minute, func() time.Time { return now })
	handler := limiter.Middleware(
		func(*http.Request) string { return "client-1" },
	)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	for attempt := 1; attempt <= 3; attempt++ {
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		want := http.StatusNoContent
		if attempt == 3 {
			want = http.StatusTooManyRequests
		}

		if recorder.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt, recorder.Code, want)
		}
	}
}

func TestRateLimiterBoundsTrackedClients(t *testing.T) {
	limiter := NewRateLimiter(1, time.Minute, func() time.Time { return time.Unix(0, 0) })
	for attempt := 0; attempt < maxTrackedRateLimitClients+100; attempt++ {
		if !limiter.Allow("client-" + strconv.Itoa(attempt)) {
			t.Fatalf("new client %d was unexpectedly rejected", attempt)
		}
	}

	if got := len(limiter.clients); got != maxTrackedRateLimitClients {
		t.Fatalf("tracked clients = %d, want %d", got, maxTrackedRateLimitClients)
	}
}

func authQuotaHandler(t *testing.T) http.Handler {
	t.Helper()
	deps := explicitTestDependencies()

	noop := http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
	)
	deps.Browser = BrowserDependencies{
		API: noop, Admin: noop, LoginPage: noop, LoginAsset: noop,
		MutationAuthorizer: func(context.Context, *http.Request) (bool, error) { return true, nil },
	}

	server, err := NewServer(deps)
	if err != nil {
		t.Fatal(err)
	}

	return server.Handler()
}

func TestAuthQuotaAllowsInvitationAndFreshPasskeyLogin(t *testing.T) {
	handler := authQuotaHandler(t)
	for _, path := range []string{
		"/invitation/accept", "/enrollment/passkey/begin", "/enrollment/passkey/finish",
		"/password", "/passkey/begin", "/factor",
	} {
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/auth"+path, nil))

		if response.Code != http.StatusNoContent {
			t.Fatalf("complete setup/login stopped at %s: %d", path, response.Code)
		}
	}
}

func TestAuthQuotaKeepsPasswordAndProofAliasesBounded(t *testing.T) {
	for name, paths := range map[string][]string{
		"password": {"/password", "/enrollment/password", "/invitation/accept", "/password/reset/finish", "/owner/password", "/password?rotate=1"},
		"proof":    {"/factor", "/passkey/begin", "/enrollment/passkey/begin", "/enrollment/passkey/finish", "/enrollment/totp/confirm", "/factor?rotate=1"},
		"email":    {"/password/reset/request", "/email/verify", "/password/reset/request?rotate=1", "/email/verify?rotate=2", "/email/verify?rotate=3", "/password/reset/request?rotate=4"},
	} {
		t.Run(name, func(t *testing.T) {
			handler := authQuotaHandler(t)
			for index, path := range paths {
				response := httptest.NewRecorder()

				handler.ServeHTTP(
					response,
					httptest.NewRequest(http.MethodPost, "/api/v1/auth"+path, nil),
				)
				want := http.StatusNoContent
				if index == 5 {
					want = http.StatusTooManyRequests
				}

				if response.Code != want {
					t.Fatalf("attempt%d %s: status%d want%d", index+1, path, response.Code, want)
				}
			}
		})
	}
}
