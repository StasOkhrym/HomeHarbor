package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRateLimiterRejectsRequestsAfterLimit(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	limiter := NewRateLimiter(2, time.Minute, func() time.Time { return now })
	handler := limiter.Middleware(func(*http.Request) string { return "client-1" })(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
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
