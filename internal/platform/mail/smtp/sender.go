// Package smtp implements authenticated mail submission over verified TLS.
// Networking stays separate from the pure mail values used by domain modules.
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	netsmtp "net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
)

const (
	StartTLS    = "starttls"
	ImplicitTLS = "tls"
)

type Config struct {
	Host     string
	Port     int
	Username string `json:"-"`
	Password string `json:"-"`
	From     string
	Mode     string
	Timeout  time.Duration
	RootCAs  *x509.CertPool `json:"-"`
}
type Sender struct {
	config Config
	tls    *tls.Config
}

func ascii(value string) bool {
	for _, r := range value {
		if r > 127 {
			return false
		}
	}

	return true
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) < 1 || len(host) > 253 {
		return false
	}

	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
				r == '-'
			if !allowed {
				return false
			}
		}
	}

	return true
}

func New(config Config) (*Sender, error) {
	invalid := func() (*Sender, error) { return nil, errors.New("invalid SMTP configuration") }

	from, err := mail.CanonicalAddress(config.From)
	if err != nil || !ascii(from) || !validHost(config.Host) || config.Port < 1 ||
		config.Port > 65535 ||
		config.Username == "" ||
		len(config.Username) > 1024 ||
		config.Password == "" ||
		len(config.Password) > 4096 ||
		strings.ContainsAny(config.Username, "\x00\r\n") ||
		strings.ContainsAny(config.Password, "\x00\r\n") ||
		config.Timeout < 100*time.Millisecond ||
		config.Timeout > 30*time.Second ||
		(config.Mode != StartTLS && config.Mode != ImplicitTLS) {
		return invalid()
	}

	config.From = from
	var roots *x509.CertPool
	if config.RootCAs != nil {
		roots = config.RootCAs.Clone()
	}

	return &Sender{
		config: config,
		tls:    &tls.Config{MinVersion: tls.VersionTLS12, ServerName: config.Host, RootCAs: roots},
	}, nil
}

func (s *Sender) encode(message mail.Message) ([]byte, string, error) {
	id, err := uuid.Parse(message.ID)

	to, addressErr := mail.CanonicalAddress(message.To)
	if err != nil || id == uuid.Nil || id.String() != message.ID || addressErr != nil ||
		len(message.Subject) < 1 ||
		len(message.Subject) > 200 ||
		strings.ContainsAny(message.Subject, "\r\n") ||
		!utf8.ValidString(message.Subject) ||
		len(message.Text) > 65536 ||
		!utf8.ValidString(message.Text) ||
		message.Date.IsZero() {
		return nil, "", mail.ErrInvalidMessage
	}

	domain := s.config.From[strings.LastIndexByte(s.config.From, '@')+1:]
	var buffer bytes.Buffer

	_, err = fmt.Fprintf(
		&buffer,
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
		(&netmail.Address{Name: "HomeHarbor", Address: s.config.From}).String(),
		(&netmail.Address{Address: to}).String(),
		mime.QEncoding.Encode("UTF-8", message.Subject),
		message.Date.UTC().Format(time.RFC1123Z),
		message.ID,
		domain,
	)
	if err != nil {
		return nil, "", mail.ErrInvalidMessage
	}

	writer := quotedprintable.NewWriter(&buffer)
	if _, err := writer.Write([]byte(message.Text)); err != nil {
		return nil, "", mail.ErrInvalidMessage
	}

	if err := writer.Close(); err != nil {
		return nil, "", mail.ErrInvalidMessage
	}

	return buffer.Bytes(), to, nil
}

// Send returns success once DATA is accepted. A later QUIT failure must not
// turn that accepted message into an automatic retry.
func (s *Sender) Send(ctx context.Context, message mail.Message) error {
	payload, to, err := s.encode(message)
	if err != nil {
		return err
	}
	defer clear(payload)

	if ctx.Err() != nil {
		return mail.ErrTemporary
	}

	operation, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	endpoint := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	dialer := net.Dialer{Timeout: s.config.Timeout}
	var connection net.Conn
	if s.config.Mode == ImplicitTLS {
		connection, err = (&tls.Dialer{NetDialer: &dialer, Config: s.tls.Clone()}).DialContext(
			operation,
			"tcp",
			endpoint,
		)
	} else {
		connection, err = dialer.DialContext(operation, "tcp", endpoint)
	}

	if err != nil {
		return failure(err)
	}
	defer func() { _ = connection.Close() }()

	stop := context.AfterFunc(operation, func() { _ = connection.Close() })
	defer stop()

	deadline, _ := operation.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return mail.ErrTemporary
	}

	client, err := netsmtp.NewClient(connection, s.config.Host)
	if err != nil {
		return failure(err)
	}
	defer func() { _ = client.Close() }()

	if s.config.Mode == StartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return mail.ErrPermanent
		}

		if err := client.StartTLS(s.tls.Clone()); err != nil {
			return failure(err)
		}
	}

	state, ok := client.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return mail.ErrPermanent
	}

	_, mechanisms := client.Extension("AUTH")
	plain := false
	for _, mechanism := range strings.Fields(mechanisms) {
		plain = plain || strings.EqualFold(mechanism, "PLAIN")
	}

	if !plain {
		return mail.ErrPermanent
	}

	if err := client.Auth(
		netsmtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host),
	); err != nil {
		return failure(err)
	}

	if !ascii(to) {
		if ok, _ := client.Extension("SMTPUTF8"); !ok {
			return mail.ErrPermanent
		}
	}

	if err := client.Mail(s.config.From); err != nil {
		return failure(err)
	}

	if err := client.Rcpt(to); err != nil {
		return failure(err)
	}

	writer, err := client.Data()
	if err != nil {
		return failure(err)
	}

	if n, err := writer.Write(payload); err != nil {
		return failure(err)
	} else if n != len(payload) {
		return mail.ErrTemporary
	}

	if err := writer.Close(); err != nil {
		return failure(err)
	}

	_ = client.Quit()

	return nil
}

func failure(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) && reply.Code >= 500 {
		return mail.ErrPermanent
	}

	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return mail.ErrPermanent
	}

	return mail.ErrTemporary
}
