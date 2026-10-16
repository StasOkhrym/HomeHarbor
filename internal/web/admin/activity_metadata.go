package admin

import "github.com/StasOkhrym/homeharbor/internal/control/audit"

func identityOptions(facets []audit.Facet, selected, all string) []ActivityOption {
	options := []ActivityOption{{Value: "", Label: all}}
	found := selected == ""
	for _, facet := range facets {
		label := facet.Name
		if !audit.PublicText(label, 128) {
			label = facet.ID
		}

		options = append(options, ActivityOption{Value: facet.ID, Label: label})
		found = found || facet.ID == selected
	}

	if !found {
		options = append(options, ActivityOption{Value: selected, Label: selected})
	}

	return options
}

func Subject(event audit.Event) string {
	if value, ok := audit.PublicEvent(event).Metadata["target_name"].(string); ok {
		return value
	}

	return ""
}

type ActivityDetail struct {
	Label string
	Value string
}

func ActivityDetails(event audit.Event) []ActivityDetail {
	metadata := audit.PublicEvent(event).Metadata
	fields := []struct{ key, label string }{
		{"device_role", "Device role"},
		{"device_platform", "Reported device platform"},
		{"os_version", "Reported OS version"},
		{"client_version", "Reported client version"},
		{"source_ip", "HTTP source IP"},
		{"overlay_ip", "Overlay IP"},
		{"browser", "Reported browser"},
		{"platform", "Reported request platform"},
		{"auth_method", "Authentication method"},
		{"reason", "Reason"},
	}
	details := []ActivityDetail{}
	for _, field := range fields {
		if value, ok := metadata[field.key].(string); ok && value != "" {
			details = append(details, ActivityDetail{Label: field.label, Value: value})
		}
	}

	return details
}
