package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/platform/httprequest"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

const (
	maxRequestBodyBytes int64 = httpresponse.MaxBodyBytes
	maxRequestIDLength        = 128
)

const companionSnapshotPath = "/api/v1/coordination/snapshot/companion"

func NewRouter(server *Server) http.Handler {
	router := chi.NewRouter()
	router.Use(requestIDMiddleware)
	router.Use(server.auditContextMiddleware)
	router.Use(securityHeadersMiddleware)
	router.Use(accessLogMiddleware(server.logger))
	// Recovery stays inside the access-log wrapper so a recovered panic is
	// recorded as a 500 response instead of escaping before the log middleware
	// can observe the completed request.
	router.Use(recoverMiddleware(server.logger))
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if server.loginAsset != nil {
		router.Get("/assets/login.js", server.loginAsset.ServeHTTP)
	}
	router.Get("/assets/admin.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(adminCSS)
	})
	router.Get("/assets/admin.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(adminScript)
	})
	router.Get("/assets/activity.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(activityScript)
	})
	router.Get("/assets/htmx-2.0.11.min.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(htmxScript)
	})
	router.Get("/readyz", func(w http.ResponseWriter, request *http.Request) {
		if server.ready != nil {
			if err := server.ready(request.Context()); err != nil {
				writeError(w, http.StatusServiceUnavailable, "service is not ready")
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	if server.metrics != nil {
		router.Handle("/metrics", server.metrics)
	}

	router.Route("/api/v1", server.registerAPI)
	router.Route("/admin", server.registerBrowserAdmin)
	return router
}

func (s *Server) clientKey(request *http.Request) string {
	return clientAddress(request, s.trustedProxy)
}

func clientAddress(request *http.Request, trusted []netip.Prefix) string {
	if ip := httprequest.ClientIP(request, trusted); ip != "" {
		return ip
	}

	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}

	return "unknown"
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().
			Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(request.URL.Path, "/api/") ||
			strings.HasPrefix(request.URL.Path, "/admin") {
			w.Header().Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, request)
	})
}

// accessLogMiddleware records only request metadata and response status. It
// deliberately excludes headers and bodies because cookies, bearer tickets,
// and invite material must never become part of structured logs.
func accessLogMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			started := time.Now()
			writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(writer, request)
			logger.Info(
				"http request",
				"method",
				request.Method,
				"path",
				request.URL.Path,
				"status",
				writer.status,
				"duration_ms",
				time.Since(started).Milliseconds(),
				"request_id",
				w.Header().Get("X-Request-ID"),
			)
		})
	}
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}

	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(body)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.ContentLength > maxRequestBodyBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}

		request.Body = http.MaxBytesReader(w, request.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, request)
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestID := request.Header.Get("X-Request-ID")
		if !validRequestID(requestID) {
			var value [16]byte

			if _, err := rand.Read(value[:]); err == nil {
				requestID = hex.EncodeToString(value[:])
			}
		}

		if requestID != "" {
			w.Header().Set("X-Request-ID", requestID)
		}

		next.ServeHTTP(w, request)
	})
}

func validRequestID(value string) bool {
	if value == "" || len(value) > maxRequestIDLength {
		return false
	}

	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '-' &&
			character != '_' &&
			character != '.' {
			return false
		}
	}

	return true
}
