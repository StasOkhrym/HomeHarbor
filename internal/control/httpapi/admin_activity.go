package httpapi

import "github.com/sokhrym/go-tunnels/internal/control/audit"

func adminActionLabel(action string) string {
	labels := map[string]string{
		"device.enrolled": "Device registered",
		"device.revoked":  "Device credentials revoked",
		"admin.bootstrap": "First administrator passkey setup",
		"admin.login":     "Passkey sign-in",
		"admin.recovery":  "Recovery sign-in",
		"admin.logout":    "Administrator sign-out",
		"admin.auth":      "Administrator authentication check",
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
	if !ok {
		return ""
	}
	if success {
		return "Succeeded"
	}
	return "Failed"
}
