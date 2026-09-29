package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/go-chi/chi/v5"
)

const maxRequestBodyBytes int64 = 1 << 20

func NewRouter(server *Server) http.Handler {
	router := chi.NewRouter()
	router.Use(requestIDMiddleware)
	router.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	if server.metrics != nil {
		router.Handle("/metrics", server.metrics)
	}

	router.Route("/api/v1", func(api chi.Router) {
		api.Use(limitRequestBody)
		if auth, ok := server.authorizer.(interface{ Handler() http.Handler }); ok {
			api.Mount("/auth", auth.Handler())
		}
		api.Post("/enrollment-tokens", server.requireAdmin(http.HandlerFunc(server.issueToken)).ServeHTTP)
		api.Post("/enroll", server.enroll)
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
