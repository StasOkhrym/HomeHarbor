package audit

// ActionOption is the public audit vocabulary shared by filters and event labels.
type ActionOption struct {
	Value    string
	Label    string
	Category string
}

// Actions returns a private copy so consumers cannot alter the event vocabulary.
func Actions() []ActionOption {
	return []ActionOption{
		{"admin.bootstrap", "First administrator passkey setup", "security"},
		{"admin.login", "Passkey sign-in", "security"},
		{"admin.recovery", "Recovery sign-in", "security"},
		{"admin.logout", "Administrator sign-out", "security"},
		{"admin.auth", "Administrator authentication check", "security"},
		{"device.enrolled", "Device registered", "devices"},
		{"device.revoked", "Device credentials revoked", "devices"},
		{"device.credential_rotated", "Device credential rotated", "devices"},
		{"device.credential_recovered", "Device credential recovered", "devices"},
		{"device.credential_claimed", "Device credential claimed", "devices"},
		{"invite.approved", "Invite approved", "access"},
	}
}

func ActionLabel(action string) string {
	for _, option := range Actions() {
		if option.Value == action {
			return option.Label
		}
	}

	return "Other activity"
}

// CategoryActions enumerates known actions. System is the complement of known
// non-system actions, so historical and future unknown events remain discoverable.
func CategoryActions(category string) ([]string, bool) {
	switch category {
	case "", "security", "devices", "access", "administrators", "system":
	default:
		return nil, false
	}

	values := make([]string, 0)
	for _, action := range Actions() {
		if category == "system" || action.Category == category {
			values = append(values, action.Value)
		}
	}

	return values, true
}
