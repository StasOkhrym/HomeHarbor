package httpapi

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/admin/*.html
var adminViews embed.FS

//go:embed static/admin.css
var adminCSS []byte

//go:embed static/admin.js
var adminScript []byte

//go:embed static/htmx-2.0.11.min.js
var htmxScript []byte

var adminTemplate = template.Must(template.New("admin").Funcs(template.FuncMap{
	"timeLabel":    func(value time.Time) string { return value.UTC().Format("02 Jan 2006, 15:04 UTC") },
	"timeISO":      func(value time.Time) string { return value.UTC().Format(time.RFC3339) },
	"actionLabel":  adminActionLabel,
	"auditOutcome": adminAuditOutcome,
}).ParseFS(adminViews, "templates/admin/*.html"))

func (s *Server) renderAdmin(w http.ResponseWriter, status int, model adminPageModel) {
	// Buffer first: a template error must produce an error response, not a
	// truncated 200 page containing an apparently successful form result.
	var output bytes.Buffer
	if err := adminTemplate.ExecuteTemplate(&output, "page", model); err != nil {
		s.logger.Error("render admin page", "error", err, "page", model.Page)
		http.Error(
			w,
			"The page could not be displayed. Please try again.",
			http.StatusInternalServerError,
		)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}
