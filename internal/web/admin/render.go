package admin

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var pageTemplate = template.Must(assets.AdminTemplate(template.FuncMap{
	"timeLabel":        func(value time.Time) string { return value.UTC().Format("02 Jan 2006, 15:04 UTC") },
	"timeISO":          func(value time.Time) string { return value.UTC().Format(time.RFC3339) },
	"actionLabel":      ActionLabel,
	"auditOutcome":     Outcome,
	"auditActor":       Actor,
	"auditCorrelation": Correlation,
	"auditRevision":    Revision,
}))

// RenderPage buffers template output so a rendering failure cannot produce a
// truncated success response for a browser mutation.
func RenderPage(w http.ResponseWriter, status int, model Page, logger *slog.Logger) {
	var output bytes.Buffer

	if err := pageTemplate.ExecuteTemplate(&output, "page", model); err != nil {
		logger.Error("render admin page", "error", err, "page", model.Page)
		http.Error(
			w,
			"The page could not be displayed. Please try again.",
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Native form POSTs use navigate mode: no-referrer would turn their
	// Origin into null and fail our strict mutation authorization. Preserve
	// same-origin forms without sending referrers to external destinations.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.WriteHeader(status)
	_, _ = w.Write(output.Bytes())
}

func RenderFragment(
	w http.ResponseWriter,
	status int,
	name string,
	model Page,
	logger *slog.Logger,
) {
	var output bytes.Buffer

	if err := pageTemplate.ExecuteTemplate(&output, name, model); err != nil {
		logger.Error("render admin fragment", "error", err, "template", name)
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
