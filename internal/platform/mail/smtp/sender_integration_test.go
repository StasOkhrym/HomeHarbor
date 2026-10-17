package smtp_test

import (
	"bufio"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/http"
	netmail "net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
	mailsmtp "github.com/StasOkhrym/homeharbor/internal/platform/mail/smtp"
)

func TestMailpitSMTPVerifiedTLSAndMIME(t *testing.T) {
	if os.Getenv("TEST_MAILPIT_CAPTURE") != "1" {
		t.Skip("owned TEST_MAILPIT_CAPTURE fixture required")
	}

	pem, err := os.ReadFile(os.Getenv("TEST_MAILPIT_CA_FILE"))
	if err != nil {
		t.Fatal("capture CA unavailable")
	}

	roots := x509.NewCertPool()

	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid capture CA")
	}

	password, err := os.ReadFile(os.Getenv("TEST_MAILPIT_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("capture credential unavailable")
	}
	defer clear(password)

	for _, mode := range []string{mailsmtp.StartTLS, mailsmtp.ImplicitTLS} {
		t.Run(mode, func(t *testing.T) {
			prefix := "TEST_MAILPIT_STARTTLS"
			if mode == mailsmtp.ImplicitTLS {
				prefix = "TEST_MAILPIT_TLS"
			}

			port, err := strconv.Atoi(os.Getenv(prefix + "_PORT"))

			if err != nil || port < 1024 || port > 65535 {
				t.Fatal("invalid capture SMTP port")
			}

			capture, err := url.Parse(os.Getenv(prefix + "_URL"))

			if err != nil || capture.Scheme != "http" || capture.Hostname() != "127.0.0.1" ||
				capture.User != nil ||
				capture.RawQuery != "" ||
				capture.Fragment != "" {
				t.Fatal("capture HTTP must be owned loopback")
			}

			config := mailsmtp.Config{
				Host:     "localhost",
				Port:     port,
				From:     "homeharbor@example.test",
				Username: "homeharbor",
				Password: strings.TrimSpace(string(password)),
				Mode:     mode,
				Timeout:  5 * time.Second,
				RootCAs:  roots,
			}
			sender, err := mailsmtp.New(config)
			if err != nil {
				t.Fatal(err)
			}

			message := mail.Message{
				ID:      uuid.NewString(),
				To:      "owner@example.test",
				Subject: "HomeHarbor · перевірка",
				Text:    "Private capture fixture\nПеревірка UTF-8\nhttps://control.example.test/admin/reset-password#token=fixture-only\n",
				Date:    time.Now().UTC().Truncate(time.Second),
			}

			if err := sender.Send(t.Context(), message); err != nil {
				t.Fatal("verified SMTP submission failed", err)
			}

			endpoint := *capture
			endpoint.Path = "/api/v1/message/latest/raw"
			client := http.Client{
				Timeout:       3 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}

			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				endpoint.String(),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}

			response, err := client.Do(request)
			if err != nil {
				t.Fatal("capture API unavailable")
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != http.StatusOK {
				t.Fatal("captured message not available", response.StatusCode)
			}

			received, err := netmail.ReadMessage(
				bufio.NewReader(io.LimitReader(response.Body, 128<<10)),
			)
			if err != nil {
				t.Fatal("invalid captured MIME")
			}

			subject, err := new(mime.WordDecoder).DecodeHeader(received.Header.Get("Subject"))

			if err != nil || subject != message.Subject {
				t.Fatal("UTF-8 subject corrupted")
			}
			if received.Header.Get("Message-Id") != "<"+message.ID+"@example.test>" ||
				received.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
				t.Fatal("unstable message ID or missing MIME encoding")
			}

			body, err := io.ReadAll(quotedprintable.NewReader(received.Body))

			if err != nil || strings.ReplaceAll(string(body), "\r\n", "\n") != message.Text {
				t.Fatal("captured text or private link corrupted")
			}

			clear(body)

			from, err := received.Header.AddressList("From")

			if err != nil || len(from) != 1 || from[0].Address != config.From {
				t.Fatal("incorrect sender")
			}

			for _, invalid := range []string{"password", "authority", "hostname"} {
				t.Run(invalid, func(t *testing.T) {
					candidate := config
					switch invalid {
					case "password":
						candidate.Password = "wrong-capture-password"
					case "authority":
						candidate.RootCAs = x509.NewCertPool()
					case "hostname":
						candidate.Host = "127.0.0.1"
					}

					rejected, err := mailsmtp.New(candidate)
					if err != nil {
						t.Fatal(err)
					}

					if err := rejected.Send(
						t.Context(),
						message,
					); !errors.Is(
						err,
						mail.ErrPermanent,
					) {
						t.Fatal("unverified or unauthenticated SMTP admitted", err)
					}
				})
			}
		})
	}
}
