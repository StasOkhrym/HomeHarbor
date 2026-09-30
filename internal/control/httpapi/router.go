package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

const maxRequestBodyBytes int64 = 1 << 20

const companionSnapshotPath = "/api/v1/coordination/snapshot/companion"

func NewRouter(server *Server) http.Handler {
	router := chi.NewRouter()
	router.Use(requestIDMiddleware)
	router.Use(securityHeadersMiddleware)
	router.Use(accessLogMiddleware(server.logger))
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	if assets, ok := server.authorizer.(interface{ LoginAssetHandler() http.Handler }); ok {
		router.Get("/assets/login.js", assets.LoginAssetHandler().ServeHTTP)
	}
	router.Get("/assets/admin.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(adminCSS)
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

	router.Route("/api/v1", func(api chi.Router) {
		api.Use(limitRequestBody)
		api.Use(server.apiLimiter.Middleware(server.clientKey))
		if auth, ok := server.authorizer.(interface{ Handler() http.Handler }); ok {
			api.Mount("/auth", server.authLimiter.Middleware(server.clientKey)(auth.Handler()))
		}
		api.Post("/enrollment-tokens", server.requireAdmin(http.HandlerFunc(server.issueToken)).ServeHTTP)
		api.Post("/enroll", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.enroll)).ServeHTTP)

		// The resource groups make the public API discoverable. The flat routes
		// below remain temporarily for already enrolled clients and are removed
		// only after the versioned API migration is complete.
		api.Route("/admin", func(admin chi.Router) {
			admin.Use(server.requireAdmin)
			admin.Post("/enrollment-tokens", http.HandlerFunc(server.issueToken).ServeHTTP)
			admin.Get("/devices", http.HandlerFunc(server.listDevices).ServeHTTP)
			if server.network != nil {
				admin.Get("/routes", http.HandlerFunc(server.listRoutes).ServeHTTP)
			}
			if server.services != nil {
				admin.Get("/services", http.HandlerFunc(server.listServices).ServeHTTP)
				admin.Get("/access-profiles", http.HandlerFunc(server.listProfiles).ServeHTTP)
			}
		})
		api.Route("/devices", func(devices chi.Router) {
			devices.Get("/", server.requireAdmin(http.HandlerFunc(server.listDevices)).ServeHTTP)
			devices.Delete("/{id}", server.requireAdmin(http.HandlerFunc(server.revokeDevice)).ServeHTTP)
			devices.Post("/credentials/rotate", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.rotateCredential)).ServeHTTP)
		})
		api.Route("/invites", func(invites chi.Router) {
			if server.invites == nil {
				return
			}
			invites.Post("/proof", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.submitInviteProof)).ServeHTTP)
			invites.Get("/{id}", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.getInvite)).ServeHTTP)
			invites.Post("/{id}/approval", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.approveInvite)).ServeHTTP)
		})
		api.Route("/services", func(services chi.Router) {
			if server.services == nil {
				return
			}
			services.Use(server.requireAdmin)
			services.Get("/", http.HandlerFunc(server.listServices).ServeHTTP)
			services.Post("/", http.HandlerFunc(server.createService).ServeHTTP)
		})
		api.Route("/coordination", func(coordination chi.Router) {
			if server.coordination != nil {
				coordination.Get("/", server.coordination.ServeHTTP)
			}
			if server.snapshots != nil {
				coordination.Post("/snapshots", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.publishSnapshot)).ServeHTTP)
				coordination.Get("/snapshot", server.requireAdmin(http.HandlerFunc(server.latestSnapshot)).ServeHTTP)
				if server.companionChallenges != nil {
					coordination.Get("/snapshot/companion-challenge", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.issueCompanionChallenge)).ServeHTTP)
					coordination.Get("/snapshot/companion", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.companionSnapshot)).ServeHTTP)
				}
			}
		})
		api.Route("/relay-sessions", func(relaySessions chi.Router) {
			if server.relayIssuer != nil {
				relaySessions.Post("/", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.issueRelaySession)).ServeHTTP)
			}
		})

		api.Post("/devices/credentials/rotate", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.rotateCredential)).ServeHTTP)
		if server.relayIssuer != nil {
			api.Post("/relay-sessions", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.issueRelaySession)).ServeHTTP)
		}
		if server.invites != nil {
			api.Post("/invites/proof", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.submitInviteProof)).ServeHTTP)
			api.Get("/invites/{id}", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.getInvite)).ServeHTTP)
			api.Post("/invites/{id}/approval", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.approveInvite)).ServeHTTP)
		}
		if server.snapshots != nil {
			api.Post("/coordination/snapshots", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.publishSnapshot)).ServeHTTP)
			api.Get("/coordination/snapshot", server.requireAdmin(http.HandlerFunc(server.latestSnapshot)).ServeHTTP)
			if server.companionChallenges != nil {
				api.Get("/coordination/snapshot/companion-challenge", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.issueCompanionChallenge)).ServeHTTP)
				api.Get("/coordination/snapshot/companion", server.deviceLimiter.Middleware(server.clientKey)(http.HandlerFunc(server.companionSnapshot)).ServeHTTP)
			}
		}
		api.Get("/devices", server.requireAdmin(http.HandlerFunc(server.listDevices)).ServeHTTP)
		api.Delete("/devices/{id}", server.requireAdmin(http.HandlerFunc(server.revokeDevice)).ServeHTTP)
		if server.network != nil {
			api.Get("/routes", server.requireAdmin(http.HandlerFunc(server.listRoutes)).ServeHTTP)
			api.Post("/routes", server.requireAdmin(http.HandlerFunc(server.advertiseRoute)).ServeHTTP)
			api.Post("/routes/{id}/approve", server.requireAdmin(http.HandlerFunc(server.approveRoute)).ServeHTTP)
			api.Post("/routes/{id}/reject", server.requireAdmin(http.HandlerFunc(server.rejectRoute)).ServeHTTP)
		}
		if server.policy != nil {
			api.Get("/policy", server.requireAdmin(http.HandlerFunc(server.latestPolicy)).ServeHTTP)
			api.Put("/policy", server.requireAdmin(http.HandlerFunc(server.replacePolicy)).ServeHTTP)
		}
		if server.services != nil {
			api.Get("/services", server.requireAdmin(http.HandlerFunc(server.listServices)).ServeHTTP)
			api.Post("/services", server.requireAdmin(http.HandlerFunc(server.createService)).ServeHTTP)
			api.Get("/access-profiles", server.requireAdmin(http.HandlerFunc(server.listProfiles)).ServeHTTP)
			api.Post("/access-profiles", server.requireAdmin(http.HandlerFunc(server.createProfile)).ServeHTTP)
		}
		if server.coordination != nil {
			api.Get("/coordination", server.coordination.ServeHTTP)
		}
	})

	router.Route("/admin", func(admin chi.Router) {
		admin.Get("/", server.requireAdmin(http.HandlerFunc(server.adminDashboard)).ServeHTTP)
		if login, ok := server.authorizer.(interface{ LoginHandler() http.Handler }); ok {
			admin.Handle("/login", login.LoginHandler())
		}
	})
	return router
}

func (s *Server) clientKey(request *http.Request) string {
	return clientAddress(request, s.trustedProxy)
}

func clientAddress(request *http.Request, trusted []netip.Prefix) string {
	remote := request.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	remoteAddr, err := netip.ParseAddr(remote)
	if err != nil {
		if request.RemoteAddr != "" {
			return request.RemoteAddr
		}
		return "unknown"
	}
	for _, prefix := range trusted {
		if !prefix.Contains(remoteAddr) {
			continue
		}
		for _, candidate := range strings.Split(request.Header.Get("X-Forwarded-For"), ",") {
			if forwarded, parseErr := netip.ParseAddr(strings.TrimSpace(candidate)); parseErr == nil {
				return forwarded.String()
			}
		}
		break
	}
	return remoteAddr.String()
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(request.URL.Path, "/api/") || strings.HasPrefix(request.URL.Path, "/admin") {
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
			logger.Info("http request", "method", request.Method, "path", request.URL.Path, "status", writer.status, "duration_ms", time.Since(started).Milliseconds(), "request_id", w.Header().Get("X-Request-ID"))
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
		if requestID == "" {
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
