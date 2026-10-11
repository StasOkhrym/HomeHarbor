package session

import (
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

// ParseForm rejects malformed browser POSTs before auth middleware reads form
// tokens. net/http's FormValue alone silently discards ParseForm errors.
func ParseForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				httpresponse.WriteError(w, http.StatusBadRequest, "invalid form body")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
