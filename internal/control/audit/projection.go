package audit

import (
	"math"
	"net/netip"
)

// SubjectSnapshot records public identity at mutation time. Reported client
// properties are descriptive only and never grant network permissions.
type SubjectSnapshot struct {
	Name          string `json:"name,omitempty"`
	Role          string `json:"role,omitempty"`
	Platform      string `json:"platform,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	OverlayIP     string `json:"overlay_ip,omitempty"`
}

func (s SubjectSnapshot) Safe() SubjectSnapshot {
	if !PublicText(s.Name, 128) {
		s.Name = ""
	}

	if !oneOf(s.Role, "client", "gateway") {
		s.Role = ""
	}

	if !Platform(s.Platform) {
		s.Platform = ""
	}

	if !PublicText(s.OSVersion, 64) {
		s.OSVersion = ""
	}

	if !PublicText(s.ClientVersion, 64) {
		s.ClientVersion = ""
	}

	if ip, err := netip.ParseAddr(s.OverlayIP); err == nil && ip.Zone() == "" {
		s.OverlayIP = ip.Unmap().String()
	} else {
		s.OverlayIP = ""
	}

	return s
}

func (s SubjectSnapshot) Metadata() map[string]any {
	s = s.Safe()
	result := map[string]any{}
	for key, value := range map[string]string{"target_name": s.Name, "device_role": s.Role, "device_platform": s.Platform, "os_version": s.OSVersion, "client_version": s.ClientVersion, "overlay_ip": s.OverlayIP} {
		if value != "" {
			result[key] = value
		}
	}

	return result
}

// PublicEvent is the read boundary for both HTML and JSON. Historical metadata
// may predate the allowlist; arbitrary fields never reach the public surface.
func PublicEvent(event Event) Event {
	text := func(key string) string { value, _ := event.Metadata[key].(string); return value }
	facts := Context{
		ActorType:      event.ActorType,
		ActorID:        event.ActorID,
		ActorName:      text("actor_name"),
		SourceIP:       text("source_ip"),
		Browser:        text("browser"),
		Platform:       text("platform"),
		Authentication: text("auth_method"),
		Reason:         text("reason"),
		CorrelationID:  text("correlation_id"),
	}
	metadata := facts.Metadata()
	subject := SubjectSnapshot{
		Name:          text("target_name"),
		Role:          text("device_role"),
		Platform:      text("device_platform"),
		OSVersion:     text("os_version"),
		ClientVersion: text("client_version"),
		OverlayIP:     text("overlay_ip"),
	}
	for key, value := range subject.Metadata() {
		metadata[key] = value
	}

	if success, ok := event.Metadata["success"].(bool); ok {
		metadata["success"] = success
	}

	if outcome := text("outcome"); oneOf(outcome, "success", "failure") {
		metadata["outcome"] = outcome
	}

	switch revision := event.Metadata["aggregate_revision"].(type) {
	case int64:
		if revision > 0 {
			metadata["aggregate_revision"] = revision
		}
	case float64:
		if revision > 0 && revision <= 1<<53 && math.Trunc(revision) == revision {
			metadata["aggregate_revision"] = revision
		}
	}

	event.Metadata = metadata

	return event
}
