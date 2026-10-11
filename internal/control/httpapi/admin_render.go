package httpapi

import (
	"bytes"
	"html/template"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var (
	adminCSS       = assets.Static("admin.css")
	adminScript    = assets.Static("admin.js")
	activityScript = assets.Static("activity.js")
	htmxScript     = assets.Static("htmx-2.0.11.min.js")
)

var adminTemplate = template.Must(assets.AdminTemplate(template.FuncMap{
	"timeLabel":        func(value time.Time) string { return value.UTC().Format("02 Jan 2006, 15:04 UTC") },
	"timeISO":          func(value time.Time) string { return value.UTC().Format(time.RFC3339) },
	"actionLabel":      adminActionLabel,
	"auditOutcome":     adminAuditOutcome,
	"auditActor":       adminAuditActor,
	"auditCorrelation": adminAuditCorrelation,
	"auditRevision":    adminAuditRevision,
}))

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

func (s *Server) renderAdminFragment(
	w http.ResponseWriter,
	status int,
	name string,
	model adminPageModel,
) {
	var output bytes.Buffer
	if err := adminTemplate.ExecuteTemplate(&output, name, model); err != nil {
		s.logger.Error("render admin fragment", "error", err, "template", name)
		http.Error(
			w,
			"Activity could not be displayed. Please try again.",
			http.StatusInternalServerError,
		)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}
