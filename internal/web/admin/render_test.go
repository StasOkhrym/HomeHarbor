package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

func TestCompanionInstructionsRequireDeploymentConfig(t *testing.T) {
	for _, page := range []string{"invites", "setup", "devices"} {
		t.Run(page, func(t *testing.T) {
			model := NewPage(page, "", "")
			if page == "devices" {
				model.Device = &devices.Device{ID: "public-client-id", Role: "client"}
			}

			response := httptest.NewRecorder()

			RenderPage(
				response,
				http.StatusOK,
				model,
				slog.New(slog.NewTextHandler(io.Discard, nil)),
			)
			body := response.Body.String()

			if response.Code != http.StatusOK {
				t.Fatalf("page failed to render: %d", response.Code)
			}
			if strings.Contains(body, ".local/") || strings.Contains(body, "go run ./cmd/") {
				t.Fatal("companion instruction assumes the server's dev checkout/configuration")
			}
			if !strings.Contains(body, "--config /path/to/admin.toml") ||
				!strings.Contains(body, "for this deployment") {
				t.Fatal(
					"instruction must identify the trusted companion's deployment configuration",
				)
			}
			if page == "setup" &&
				!strings.Contains(body, "--manifest /path/to/initial-snapshot.toml") {
				t.Fatal("initial publication must use an explicitly reviewed deployment manifest")
			}
		})
	}
}
