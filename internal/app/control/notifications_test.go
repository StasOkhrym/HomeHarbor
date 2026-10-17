package control

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

type emptyMailQueue struct{}

func (emptyMailQueue) Claim(context.Context) (notifications.Delivery, bool, error) {
	return notifications.Delivery{}, false, nil
}

func (emptyMailQueue) Finish(context.Context, notifications.Delivery, notifications.Outcome) error {
	return nil
}

func TestMailRuntimeDisabledDoesNotOpenSecrets(t *testing.T) {
	cfg := config.Control{}
	cfg.SMTP.CAFile = "/missing/private-ca"

	runtime, err := buildNotifications(cfg, nil, nil)

	if err != nil || runtime != nil {
		t.Fatal("disabled mail initialized private dependencies", err)
	}
}

func TestMailRuntimeBuildDoesNotDialSMTP(t *testing.T) {
	cfg := mailRuntimeConfig()

	runtime, err := buildNotifications(cfg, emptyMailQueue{}, nil)

	if err != nil || runtime == nil || runtime.codec == nil || runtime.worker == nil {
		t.Fatal("enabled mail could not be composed without dialing", err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	cancel()

	if err := runtime.worker.Run(ctx); err != nil {
		t.Fatal("cancelled mail worker did not stop", err)
	}
}

func TestMailRuntimeRejectsInvalidTrustWithoutPrivateDiagnostic(t *testing.T) {
	cfg := mailRuntimeConfig()
	for _, content := range []string{"PRIVATE_INVALID_CA"} {
		path := filepath.Join(t.TempDir(), "private-ca.pem")

		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}

		cfg.SMTP.CAFile = path

		_, err := buildNotifications(cfg, emptyMailQueue{}, nil)

		if err == nil || strings.Contains(err.Error(), content) ||
			strings.Contains(err.Error(), path) {
			t.Fatal("invalid trust admitted or private diagnostic exposed", err)
		}
	}
}

func mailRuntimeConfig() config.Control {
	cfg := config.Control{}
	cfg.SMTP = config.SMTP{
		Enabled:  true,
		Host:     "unreachable.invalid",
		Port:     587,
		Username: "private-user",
		Password: "private-password",
		From:     "homeharbor@example.test",
		Mode:     "starttls",
		Timeout:  time.Second,
	}
	cfg.Auth.CeremonyEncryptionKey = strings.Repeat("x", 32)
	cfg.Auth.RPOrigin = "https://control.example.test"

	return cfg
}
