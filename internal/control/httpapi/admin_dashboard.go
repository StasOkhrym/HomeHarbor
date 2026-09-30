package httpapi

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
)

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	routes := []controlroutes.Advertisement{}
	if s.routes != nil {
		routes, _ = s.routes.List(r.Context())
	}
	services := []controlservices.Service{}
	profiles := []controlservices.AccessProfile{}
	if s.services != nil {
		services, _ = s.services.List(r.Context())
		profiles, _ = s.services.Profiles(r.Context())
	}
	auditEvents := []audit.Event{}
	if s.audit != nil {
		auditEvents, _ = s.audit.List(r.Context(), defaultAuditLimit)
	}
	policyJSON := "[]"
	if s.policy != nil {
		if current, policyErr := s.policy.Latest(r.Context()); policyErr == nil {
			if encoded, marshalErr := json.MarshalIndent(current.Rules, "", "  "); marshalErr == nil {
				policyJSON = string(encoded)
			}
		}
	}
	if err := adminTemplate.Execute(w, map[string]any{
		"Devices":    list,
		"HasNetwork": s.routes != nil,
		"Routes":     routes,
		"Services":   services,
		"Profiles":   profiles,
		"Audit":      auditEvents,
		"PolicyJSON": policyJSON,
		"CSRF":       csrfFormToken(r),
		"Notice":     r.URL.Query().Get("notice"),
	}); err != nil {
		s.logger.Error("render admin", "error", err)
	}
}

//go:embed templates/admin.html
var adminPage []byte

//go:embed static/admin.css
var adminCSS []byte

var adminTemplate = template.Must(template.New("admin").Parse(string(adminPage)))
