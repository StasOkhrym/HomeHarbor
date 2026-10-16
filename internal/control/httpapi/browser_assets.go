package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var (
	adminCSS          = assets.Static("admin.css")
	adminScript       = assets.Static("admin.js")
	activityScript    = assets.Static("activity.js")
	livePollScript    = assets.Static("live-poll.js")
	connectionsScript = assets.Static("connections.js")
	htmxScript        = assets.Static("htmx-2.0.11.min.js")
)

func registerBrowserAssets(router chi.Router) {
	router.Get("/assets/admin.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		_, _ = w.Write(adminCSS)
	})
	for _, asset := range []struct {
		path  string
		data  []byte
		cache string
	}{
		{"/assets/admin.js", adminScript, "public, max-age=3600, immutable"},
		{"/assets/activity.js", activityScript, "public, max-age=3600, immutable"},
		{"/assets/live-poll.js", livePollScript, "public, max-age=3600, immutable"},
		{"/assets/connections.js", connectionsScript, "public, max-age=3600, immutable"},
		{"/assets/htmx-2.0.11.min.js", htmxScript, "public, max-age=31536000, immutable"},
	} {
		router.Get(asset.path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", asset.cache)
			_, _ = w.Write(asset.data)
		})
	}
}
