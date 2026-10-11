package httpapi

import (
	"net/http"

	webadmin "github.com/StasOkhrym/homeharbor/internal/web/admin"
	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var (
	adminCSS       = assets.Static("admin.css")
	adminScript    = assets.Static("admin.js")
	activityScript = assets.Static("activity.js")
	htmxScript     = assets.Static("htmx-2.0.11.min.js")
)

func (s *Server) renderAdmin(w http.ResponseWriter, status int, model webadmin.Page) {
	webadmin.RenderPage(w, status, model, s.logger)
}

func (s *Server) renderAdminFragment(
	w http.ResponseWriter,
	status int,
	name string,
	model webadmin.Page,
) {
	webadmin.RenderFragment(w, status, name, model, s.logger)
}
