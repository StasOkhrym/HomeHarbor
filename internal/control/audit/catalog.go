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
		{"admin.login", "Administrator sign-in", "security"},
		{"admin.recovery", "Recovery sign-in", "security"},
		{"admin.account_configured", "Owner email and password configured", "administrators"},
		{"admin.totp_added", "Authenticator added", "security"},
		{"admin.totp_removed", "Authenticator removed", "security"},
		{"admin.passkey_added", "Passkey added", "security"},
		{"admin.passkey_removed", "Passkey removed", "security"},
		{"admin.recovery_codes_replaced", "Recovery codes replaced", "security"},
		{"admin.password_reset_requested", "Password reset requested", "security"},
		{"admin.password_reset", "Administrator password reset", "security"},
		{"admin.verification_requested", "Email confirmation requested", "administrators"},
		{"admin.email_verified", "Email address confirmed", "administrators"},
		{"admin.invited", "Administrator invited", "administrators"},
		{"admin.invitation_accepted", "Administrator invitation accepted", "administrators"},
		{"admin.account_activated", "Administrator account activated", "administrators"},
		{"admin.revoked", "Administrator access revoked", "administrators"},
		{"admin.smtp_test_requested", "Email delivery test requested", "administrators"},
		{"admin.sessions_revoked", "All administrator sessions ended", "security"},
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
