package config

import (
	"errors"
	"time"

	mailsmtp "github.com/StasOkhrym/homeharbor/internal/platform/mail/smtp"
)

// SMTP is optional. Secrets are resolved only when delivery is explicitly enabled.
type SMTP struct {
	Enabled      bool          `toml:"enabled"`
	Host         string        `toml:"host"`
	Port         int           `toml:"port"`
	Username     string        `toml:"username"`
	Password     string        `toml:"password"      json:"-"`
	PasswordFile string        `toml:"password_file"`
	From         string        `toml:"from"`
	Mode         string        `toml:"mode"`
	Timeout      time.Duration `toml:"timeout"`
	CAFile       string        `toml:"ca_file"`
}

func defaultSMTP() SMTP { return SMTP{Port: 587, Mode: mailsmtp.StartTLS, Timeout: 10 * time.Second} }

// SubmissionConfig is transport configuration only; it performs no network I/O.
// The composition root loads an optional CA file into this configuration.
func (s SMTP) SubmissionConfig() mailsmtp.Config {
	return mailsmtp.Config{
		Host:     s.Host,
		Port:     s.Port,
		Username: s.Username,
		Password: s.Password,
		From:     s.From,
		Mode:     s.Mode,
		Timeout:  s.Timeout,
	}
}

func (s SMTP) validate() error {
	if !s.Enabled {
		return nil
	}

	if _, err := mailsmtp.New(s.SubmissionConfig()); err != nil {
		return errors.New(
			"smtp requires valid host/from/port, credentials, a verified TLS mode and a timeout within 100ms..30s",
		)
	}

	return nil
}
