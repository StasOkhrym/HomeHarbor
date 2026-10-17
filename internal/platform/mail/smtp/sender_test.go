package smtp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
	mailsmtp "github.com/StasOkhrym/homeharbor/internal/platform/mail/smtp"
)

func smtpConfig() mailsmtp.Config {
	return mailsmtp.Config{
		Host:     "smtp.example.test",
		Port:     587,
		Username: "private-user",
		Password: "private-password",
		From:     "homeharbor@example.test",
		Mode:     mailsmtp.StartTLS,
		Timeout:  time.Second,
	}
}

func TestSMTPRequiresVerifiedTLSAndCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*mailsmtp.Config)
	}{
		{"plaintext", func(c *mailsmtp.Config) { c.Mode = "plaintext" }},
		{"missing-mode", func(c *mailsmtp.Config) { c.Mode = "" }},
		{"invalid-port", func(c *mailsmtp.Config) { c.Port = 0 }},
		{"url-host", func(c *mailsmtp.Config) { c.Host = "smtp://private-user:private-password@smtp.example.test" }},
		{"missing-user", func(c *mailsmtp.Config) { c.Username = "" }},
		{"missing-password", func(c *mailsmtp.Config) { c.Password = "" }},
		{"null-password", func(c *mailsmtp.Config) { c.Password = "private\x00password" }},
		{"unbounded-timeout", func(c *mailsmtp.Config) { c.Timeout = 0 }},
		{"excessive-timeout", func(c *mailsmtp.Config) { c.Timeout = time.Minute }},
		{"injected-from", func(c *mailsmtp.Config) { c.From = "homeharbor@example.test\r\nBcc:other@example.test" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := smtpConfig()

			tc.change(&cfg)

			if _, err := mailsmtp.New(cfg); err == nil {
				t.Fatal("unsafe SMTP configuration accepted")
			} else if strings.Contains(err.Error(), "private-") {
				t.Fatal("configuration error exposed credentials")
			}
		})
	}

	for _, mode := range []string{mailsmtp.StartTLS, mailsmtp.ImplicitTLS} {
		cfg := smtpConfig()
		cfg.Mode = mode

		if _, err := mailsmtp.New(cfg); err != nil {
			t.Fatal("verified TLS mode unavailable", err)
		}
	}
}

func TestSMTPRejectsInvalidMessagesBeforeConnecting(t *testing.T) {
	sender, err := mailsmtp.New(smtpConfig())
	if err != nil {
		t.Fatal(err)
	}

	for _, change := range []string{"id", "recipient", "subject", "body", "date"} {
		t.Run(change, func(t *testing.T) {
			message := mail.Message{
				ID:      uuid.NewString(),
				To:      "owner@example.test",
				Subject: "HomeHarbor",
				Text:    "private fixture",
				Date:    time.Now().UTC(),
			}
			switch change {
			case "id":
				message.ID = "not-a-uuid"
			case "recipient":
				message.To = "owner@example.test\r\nBcc:other@example.test"
			case "subject":
				message.Subject = "subject\r\nBcc:other@example.test"
			case "body":
				message.Text = strings.Repeat("x", 65537)
			case "date":
				message.Date = time.Time{}
			}

			if err := sender.Send(t.Context(), message); !errors.Is(err, mail.ErrInvalidMessage) {
				t.Fatal("invalid message reached transport", err)
			}
		})
	}
}

func TestSMTPHonorsAlreadyCanceledContext(t *testing.T) {
	sender, err := mailsmtp.New(smtpConfig())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	cancel()
	message := mail.Message{
		ID:      uuid.NewString(),
		To:      "owner@example.test",
		Subject: "HomeHarbor",
		Text:    "private fixture",
		Date:    time.Now().UTC(),
	}

	if err := sender.Send(ctx, message); !errors.Is(err, mail.ErrTemporary) {
		t.Fatal("cancelled send not stopped", err)
	}
}
