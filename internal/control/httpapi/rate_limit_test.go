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
	for _, options := range [][]ServerOption{
		{WithRateLimits(6, 12, 140, 2*time.Second), WithSharedRateLimits(unavailableLimitStore{})},
		{WithSharedRateLimits(unavailableLimitStore{}), WithRateLimits(6, 12, 140, 2*time.Second)},
		{WithRateLimits(6, 12, 140, 2*time.Second), WithSharedRateLimits(nil)},
	} {
		s := NewServer(nil, nil, options...)
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
