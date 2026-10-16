package admin

import (
	"log/slog"
	"net/http"
	"time"
)

// ActivityFragment serves the bounded live view behind the caller's session
// middleware. The shared page template renders the same rows as the full page.
func ActivityFragment(reader ActivityReader, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		model := Page{Page: "activity"}
		activity, status := loadActivity(r.Context(), reader, r.URL.Query(), time.Now())
		model.Activity = activity
		RenderFragment(w, status, "activity-feed", model, logger)
	}
}
