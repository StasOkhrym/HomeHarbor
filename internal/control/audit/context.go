package audit

import (
	"context"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Context contains public facts only. Authentication boundaries supply the
// actor after proof succeeds; transport observations never establish identity.
type Context struct {
	ActorType      string `json:"actor_type,omitempty"`
	ActorID        string `json:"actor_id,omitempty"`
	ActorName      string `json:"actor_name,omitempty"`
	SourceIP       string `json:"source_ip,omitempty"`
	Browser        string `json:"browser,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Authentication string `json:"auth_method,omitempty"`
	Reason         string `json:"reason,omitempty"`
	CorrelationID  string `json:"correlation_id,omitempty"`
}

type contextKey struct{}

func WithContext(ctx context.Context, facts Context) context.Context {
	return context.WithValue(ctx, contextKey{}, facts.Safe())
}

func FromContext(ctx context.Context) Context {
	facts, _ := ctx.Value(contextKey{}).(Context)
	return facts
}

// Safe drops invalid optional observations. Unknown values are never coerced
// into authenticated identities or copied verbatim to durable logs.
func (c Context) Safe() Context {
	if !oneOf(c.ActorType, "admin", "device", "companion", "system") || !safeIdentifier(c.ActorID) {
		c.ActorType, c.ActorID, c.ActorName = "unknown", "", ""
	} else if !PublicText(c.ActorName, 128) {
		c.ActorName = ""
	}

	if ip, err := netip.ParseAddr(c.SourceIP); err == nil && ip.Zone() == "" {
		c.SourceIP = ip.Unmap().String()
	} else {
		c.SourceIP = ""
	}

	if !oneOf(c.Browser, "Safari", "Chrome", "Firefox", "Edge", "Other") {
		c.Browser = ""
	}

	if !Platform(c.Platform) {
		c.Platform = ""
	}

	if !oneOf(
		c.Authentication,
		"passkey",
		"password_totp",
		"password_passkey",
		"password_recovery",
		"device_credential",
		"companion_signature",
		"identity_proof",
	) {
		c.Authentication = ""
	}

	if !oneOf(
		c.Reason,
		"invalid_credentials",
		"expired",
		"revoked",
		"rate_limited",
		"invalid_proof",
		"account_conflict",
		"signed_out",
	) {
		c.Reason = ""
	}

	if !safeIdentifier(c.CorrelationID) {
		c.CorrelationID = ""
	}

	return c
}

// Metadata returns a fresh allowlisted map; it has no secret-bearing input.
func (c Context) Metadata() map[string]any {
	c = c.Safe()
	result := map[string]any{}
	for key, value := range map[string]string{"actor_name": c.ActorName, "source_ip": c.SourceIP, "browser": c.Browser, "platform": c.Platform, "auth_method": c.Authentication, "reason": c.Reason, "correlation_id": c.CorrelationID} {
		if value != "" {
			result[key] = value
		}
	}

	return result
}

func Platform(value string) bool {
	return oneOf(value, "ios", "macos", "windows", "linux", "android", "unknown")
}

// PublicText bounds human-facing names and reported versions. Callers must
// still choose a public field; this is not a sanitizer for arbitrary secrets.
func PublicText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}

	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}

	return true
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}

	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("-_.:@", r) {
			continue
		}

		return false
	}

	return true
}

func oneOf(value string, values ...string) bool {
	for _, v := range values {
		if value == v {
			return true
		}
	}

	return false
}
