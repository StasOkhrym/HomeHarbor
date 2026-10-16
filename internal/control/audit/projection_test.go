package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicProjectionDropsUnknownAndMalformedMetadata(t *testing.T) {
	original := Event{ActorType: "admin", ActorID: "a-1", Metadata: map[string]any{
		"success":        true,
		"actor_name":     "Olena",
		"source_ip":      "192.0.2.8",
		"target_name":    "Kitchen Mac",
		"platform":       "macos",
		"os_version":     "15.0",
		"authorization":  "Bearer SECRET_TOKEN",
		"browser":        "SECRET_BROWSER",
		"reason":         "failure SECRET_ERROR",
		"correlation_id": "request\nSECRET_HEADER",
		"raw_user_agent": "SECRET_UA",
		"nested":         map[string]any{"password": "SECRET_PASSWORD"},
	}}

	projected := PublicEvent(original)

	data, _ := json.Marshal(projected)

	if strings.Contains(string(data), "SECRET") ||
		projected.Metadata["target_name"] != "Kitchen Mac" ||
		projected.Metadata["success"] != true ||
		projected.Metadata["source_ip"] != "192.0.2.8" {
		t.Fatalf("unsafe/incomplete projection: %s", data)
	}
	if original.Metadata["authorization"] == nil {
		t.Fatal("projection mutated source")
	}
}
