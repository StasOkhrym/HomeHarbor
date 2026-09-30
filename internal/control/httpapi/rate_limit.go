package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimitStore is owned by the HTTP consumer, not by its Redis adapter.
type RateLimitStore interface {
	Allow(context.Context, string, string, int, time.Duration) (bool, time.Duration, error)
}

type rateWindow struct {
	started time.Time
	count   int
}

const maxTrackedRateLimitClients = 10_000

// RateLimiter is a deliberately small fixed-window limiter for unauthenticated
// endpoints. It bounds credential guessing without pretending to be a global
// distributed quota; multiple control replicas should add a shared edge limit.
type RateLimiter struct {
	shared RateLimitStore
	bucket string
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	clients map[string]rateWindow
}

// NewSharedRateLimiter never falls back to a process-local quota. The memory
// constructor remains available for deterministic unit tests only.
func NewSharedRateLimiter(store RateLimitStore, bucket string, limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{shared: store, bucket: bucket, limit: limit, window: window}
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
		if !ok && len(l.clients) >= maxTrackedRateLimitClients {
			// The limiter is process-local, so an attacker can otherwise exhaust
			// heap memory simply by rotating source addresses. Evict the oldest
			// window before admitting a new key; the deployment-level proxy still
			// provides the distributed quota for multi-instance control planes.
			var oldestKey string
			var oldest time.Time
			for candidate, window := range l.clients {
				if oldestKey == "" || window.started.Before(oldest) {
					oldestKey = candidate
					oldest = window.started
				}
			}

			if oldestKey != "" {
				delete(l.clients, oldestKey)
			}
		}

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
			allowed, retry := false, l.window
			if l.shared != nil {
				ctx, cancel := context.WithTimeout(r.Context(), time.Second)
				var err error
				allowed, retry, err = l.shared.Allow(ctx, l.bucket, key(r), l.limit, l.window)
				cancel()
				if err != nil {
					writeError(w, http.StatusServiceUnavailable, "security state unavailable")
					return
				}
			} else if l.clients != nil {
				allowed = l.Allow(key(r))
			} else {
				writeError(w, http.StatusServiceUnavailable, "security state unavailable")
				return
			}
			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(max(1, int64((retry+time.Second-1)/time.Second)), 10))
				writeError(w, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
