package httpapi

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

type rateWindow struct {
	started time.Time
	count   int
}

// RateLimiter is a deliberately small fixed-window limiter for unauthenticated
// endpoints. It bounds credential guessing without pretending to be a global
// distributed quota; multiple control replicas should add a shared edge limit.
type RateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	clients map[string]rateWindow
}

func NewRateLimiter(limit int, window time.Duration, now func() time.Time) *RateLimiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{limit: limit, window: window, now: now, clients: make(map[string]rateWindow)}
}

func (l *RateLimiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	current, ok := l.clients[key]
	if !ok || !now.Before(current.started.Add(l.window)) {
		l.clients[key] = rateWindow{started: now, count: 1}
		return true
	}
	if current.count >= l.limit {
		return false
	}
	current.count++
	l.clients[key] = current
	return true
}

func (l *RateLimiter) Middleware(key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.Allow(key(r)) {
				w.Header().Set("Retry-After", strconv.FormatInt(int64(l.window/time.Second), 10))
				writeError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
