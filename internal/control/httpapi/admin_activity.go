package httpapi

import (
	"math"
	"net/http"
	"net/url"
	"strconv"

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

var adminActionLabels = map[string]string{
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

func adminActionLabel(action string) string {
	if label, ok := adminActionLabels[action]; ok {
		return label
	}
	return "Other activity"
}

func adminAuditActor(event audit.Event) string {
	if event.ActorType == "" || event.ActorType == "unknown" || event.ActorID == "" {
		return "Unknown actor"
	}
	return event.ActorType + " / " + event.ActorID
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

func adminAuditRevision(event audit.Event) string {
	switch value := event.Metadata["aggregate_revision"].(type) {
	case int64:
		if value > 0 {
			return strconv.FormatInt(value, 10)
		}
	case float64:
		if value > 0 && value <= 1<<53 && math.Trunc(value) == value {
			return strconv.FormatInt(int64(value), 10)
		}
	}
	return ""
}
