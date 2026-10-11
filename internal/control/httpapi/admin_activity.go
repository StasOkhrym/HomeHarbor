package httpapi

import (
	"net/http"

	webadmin "github.com/StasOkhrym/homeharbor/internal/web/admin"
)

func (s *Server) adminActivityFragment(w http.ResponseWriter, r *http.Request) {
	model := webadmin.Page{Page: "activity"}
	activity, status := webadmin.LoadActivity(r.Context(), s.audit, r.URL.Query())
	model.Activity = activity
	s.renderAdminFragment(w, status, "activity-feed", model)
}
