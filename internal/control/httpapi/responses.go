package httpapi

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	return httpresponse.DecodeJSON(w, r, destination)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	httpresponse.WriteJSON(w, status, value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	httpresponse.WriteError(w, status, message)
}

func writeErrorCode(w http.ResponseWriter, status int, code, message string) {
	httpresponse.WriteErrorCode(w, status, code, message)
}

func recoverMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if value := recover(); value != nil {
					// Panic values can contain request-derived secrets or database
					// details. Keep the log useful for alerting without turning it into
					// a second credential or internal-error disclosure channel.
					logger.Error("HTTP panic", "panic_type", fmt.Sprintf("%T", value))
					writeError(w, http.StatusInternalServerError, "internal server error")
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
