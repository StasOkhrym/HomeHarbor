package httpapi

import (
	"net/http"
	"net/url"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

const defaultActivityLimit = 100

func (s *Server) adminActivityFragment(w http.ResponseWriter, r *http.Request) {
	model := adminPageModel{
		Page: "activity", AuditLimit: defaultActivityLimit,
		Values: url.Values{}, FieldErrors: map[string]string{},
	}
	status := s.loadAdminAudit(r, &model)
	s.renderAdminFragment(w, status, "activity-feed", model)
}

func adminActionLabel(action string) string {
	labels := map[string]string{
		"device.enrolled":             "Device registered",
		"device.revoked":              "Device credentials revoked",
		"device.credential_rotated":   "Device credential rotated",
		"device.credential_recovered": "Device credential recovered",
		"device.credential_claimed":   "Device credential claimed",
		"invite.approved":             "Invite approved",
		"admin.bootstrap":             "First administrator passkey setup",
		"admin.login":                 "Passkey sign-in",
		"admin.recovery":              "Recovery sign-in",
		"admin.logout":                "Administrator sign-out",
		"admin.auth":                  "Administrator authentication check",
	}
	if label, ok := labels[action]; ok {
		return label
	}
	return "Other activity"
}

// Missing outcome metadata is unknown, not success. Domain events without an
// auth outcome use their action label; arbitrary metadata is not rendered.
func adminAuditOutcome(event audit.Event) string {
	success, ok := event.Metadata["success"].(bool)
	if ok {
		if success {
			return "Succeeded"
		}
		return "Failed"
	}
	switch event.Metadata["outcome"] {
	case "success":
		return "Succeeded"
	case "failure":
		return "Failed"
	}
	return "Outcome unknown"
}

func adminAuditCorrelation(event audit.Event) string {
	correlation, _ := event.Metadata["correlation_id"].(string)
	return correlation
}
