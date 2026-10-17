package control

import (
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	mailsmtp "github.com/StasOkhrym/homeharbor/internal/platform/mail/smtp"
)

type notificationRuntime struct {
	codec  *notifications.Codec
	worker *notifications.Worker
}

// buildNotifications performs no network I/O. Optional private trust applies only
// to this SMTP connection; it never modifies the user's or system trust store.
func buildNotifications(
	cfg config.Control,
	queue notifications.DeliveryQueue,
	logger *slog.Logger,
) (*notificationRuntime, error) {
	if !cfg.SMTP.Enabled {
		return nil, nil
	}

	submission := cfg.SMTP.SubmissionConfig()
	if cfg.SMTP.CAFile != "" {
		roots, err := readMailRoots(cfg.SMTP.CAFile)
		if err != nil {
			return nil, err
		}

		submission.RootCAs = roots
	}

	sender, err := mailsmtp.New(submission)
	if err != nil {
		return nil, errors.New("configure mail submission")
	}

	codec, err := notifications.NewCodec([]byte(cfg.Auth.CeremonyEncryptionKey), cfg.Auth.RPOrigin)
	if err != nil {
		return nil, errors.New("configure private mail payloads")
	}

	worker, err := notifications.NewWorker(queue, codec, sender, logger, nil)
	if err != nil {
		return nil, err
	}

	return &notificationRuntime{codec: codec, worker: worker}, nil
}

func readMailRoots(path string) (*x509.CertPool, error) {
	unavailable := errors.New("SMTP trust file must contain valid bounded PEM certificates")

	file, err := os.Open(path)
	if err != nil {
		return nil, unavailable
	}
	defer func() { _ = file.Close() }()

	const maximum = 1 << 20

	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) > maximum {
		return nil, unavailable
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(payload) {
		return nil, unavailable
	}

	return roots, nil
}
