package httpapi

import (
	"net/http"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/platform/httprequest"
)

func (s *Server) auditContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		browser, platform := coarseClient(r.UserAgent())
		ctx := audit.WithContext(r.Context(), audit.Context{
			SourceIP: httprequest.ClientIP(r, s.trustedProxy), Browser: browser, Platform: platform,
			CorrelationID: w.Header().Get("X-Request-ID"),
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// These observations are reported by the client, not attested device facts.
// No raw user agent or detailed browser fingerprint is retained.
func coarseClient(ua string) (browser, platform string) {
	browser, platform = "Other", "unknown"
	if len(ua) > 2048 {
		return
	}

	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "Firefox/"), strings.Contains(ua, "FxiOS/"):
		browser = "Firefox"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}

	switch {
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		platform = "ios"
	case strings.Contains(ua, "Android"):
		platform = "android"
	case strings.Contains(ua, "Macintosh"):
		platform = "macos"
	case strings.Contains(ua, "Windows"):
		platform = "windows"
	case strings.Contains(ua, "Linux"):
		platform = "linux"
	}

	return
}
