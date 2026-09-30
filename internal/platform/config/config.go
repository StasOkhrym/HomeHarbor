package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Control struct {
	Server        Server          `toml:"server"`
	Database      Database        `toml:"database"`
	Auth          Auth            `toml:"auth"`
	Relay         Relay           `toml:"relay"`
	Networking    Networking      `toml:"networking"`
	DNS           DNS             `toml:"dns"`
	Security      ControlSecurity `toml:"security"`
	Observability Observability   `toml:"observability"`
}

type Server struct {
	ListenAddress string `toml:"listen_address"`
	PublicURL     string `toml:"public_url"`
}

type Database struct {
	URL          string `toml:"url"`
	Password     string `toml:"password"`
	PasswordFile string `toml:"password_file"`
}

type Auth struct {
	RPID                      string `toml:"rp_id"`
	RPOrigin                  string `toml:"rp_origin"`
	SessionSigningKey         string `toml:"session_signing_key"`
	SessionSigningKeyFile     string `toml:"session_signing_key_file"`
	CeremonyEncryptionKey     string `toml:"ceremony_encryption_key"`
	CeremonyEncryptionKeyFile string `toml:"ceremony_encryption_key_file"`
	SessionTTL                string `toml:"session_ttl"`
	CeremonyTTL               string `toml:"ceremony_ttl"`
}

// SessionDuration returns the duration already checked by Control.validate.
func (a Auth) SessionDuration() time.Duration {
	duration, _ := time.ParseDuration(a.SessionTTL)
	return duration
}

// CeremonyDuration returns the duration already checked by Control.validate.
func (a Auth) CeremonyDuration() time.Duration {
	duration, _ := time.ParseDuration(a.CeremonyTTL)
	return duration
}

type Relay struct {
	PublicURL     string `toml:"public_url"`
	TicketKey     string `toml:"ticket_key"`
	TicketKeyFile string `toml:"ticket_key_file"`
	TicketTTL     string `toml:"ticket_ttl"`
}

type Networking struct {
	NetworkID string `toml:"network_id"`
}

type DNS struct {
	Enabled bool `toml:"enabled"`
}

type ControlSecurity struct {
	RootPublicKeyFile string   `toml:"root_public_key_file"`
	TrustedProxyCIDRs []string `toml:"trusted_proxy_cidrs"`
}

type Observability struct {
	MetricsAddress string `toml:"metrics_address"`
}

type RelayServer struct {
	Server struct {
		ListenAddress string `toml:"listen_address"`
	} `toml:"server"`
	Security struct {
		TicketKey     string `toml:"ticket_key"`
		TicketKeyFile string `toml:"ticket_key_file"`
	} `toml:"security"`
}

func LoadRelayServer(path string) (RelayServer, error) {
	var cfg RelayServer
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("decode relay config: %w", err)
	}
	if value := os.Getenv("GO_TUNNELS_RELAY_LISTEN_ADDRESS"); value != "" {
		cfg.Server.ListenAddress = value
	}
	if value := os.Getenv("GO_TUNNELS_RELAY_TICKET_KEY"); value != "" {
		cfg.Security.TicketKey = value
	}
	if cfg.Security.TicketKeyFile != "" {
		value, err := os.ReadFile(cfg.Security.TicketKeyFile)
		if err != nil {
			return cfg, fmt.Errorf("read relay ticket key: %w", err)
		}
		cfg.Security.TicketKey = strings.TrimSpace(string(value))
	}
	if cfg.Server.ListenAddress == "" || len(cfg.Security.TicketKey) < 32 {
		return cfg, errors.New("relay listen_address and a ticket key of at least 32 bytes are required")
	}
	return cfg, nil
}

func LoadControl(path string) (Control, error) {
	var cfg Control
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Control{}, fmt.Errorf("decode control config: %w", err)
	}
	if value := os.Getenv("GO_TUNNELS_SERVER_LISTEN_ADDRESS"); value != "" {
		cfg.Server.ListenAddress = value
	}
	if value := os.Getenv("GO_TUNNELS_DATABASE_URL"); value != "" {
		cfg.Database.URL = value
	}
	if value := os.Getenv("GO_TUNNELS_AUTH_SESSION_SIGNING_KEY"); value != "" {
		cfg.Auth.SessionSigningKey = value
	}
	if value := os.Getenv("GO_TUNNELS_AUTH_CEREMONY_ENCRYPTION_KEY"); value != "" {
		cfg.Auth.CeremonyEncryptionKey = value
	}
	if value := os.Getenv("GO_TUNNELS_RELAY_TICKET_KEY"); value != "" {
		cfg.Relay.TicketKey = value
	}
	if cfg.Database.PasswordFile != "" {
		value, err := os.ReadFile(cfg.Database.PasswordFile)
		if err != nil {
			return Control{}, fmt.Errorf("read database password file: %w", err)
		}
		cfg.Database.Password = strings.TrimSpace(string(value))
	}
	if cfg.Auth.SessionSigningKey == "" && cfg.Auth.SessionSigningKeyFile != "" {
		value, err := readSecret(cfg.Auth.SessionSigningKeyFile, "session signing key")
		if err != nil {
			return Control{}, err
		}
		cfg.Auth.SessionSigningKey = value
	}
	if cfg.Auth.CeremonyEncryptionKey == "" && cfg.Auth.CeremonyEncryptionKeyFile != "" {
		value, err := readSecret(cfg.Auth.CeremonyEncryptionKeyFile, "ceremony encryption key")
		if err != nil {
			return Control{}, err
		}
		cfg.Auth.CeremonyEncryptionKey = value
	}
	if cfg.Relay.TicketKey == "" && cfg.Relay.TicketKeyFile != "" {
		value, err := readSecret(cfg.Relay.TicketKeyFile, "relay ticket key")
		if err != nil {
			return Control{}, err
		}
		cfg.Relay.TicketKey = value
	}
	if err := cfg.validate(); err != nil {
		return Control{}, err
	}
	return cfg, nil
}

func (c Control) validate() error {
	var missing []string
	values := []struct{ name, value string }{
		{"server.listen_address", c.Server.ListenAddress},
		{"server.public_url", c.Server.PublicURL},
		{"database.url", c.Database.URL},
		{"auth.rp_id", c.Auth.RPID},
		{"auth.rp_origin", c.Auth.RPOrigin},
		{"auth.session_signing_key", c.Auth.SessionSigningKey},
		{"auth.ceremony_encryption_key", c.Auth.CeremonyEncryptionKey},
		{"auth.session_ttl", c.Auth.SessionTTL},
		{"auth.ceremony_ttl", c.Auth.CeremonyTTL},
		{"relay.public_url", c.Relay.PublicURL},
	}
	for _, field := range values {
		if strings.TrimSpace(field.value) == "" {
			missing = append(missing, field.name)
		}
	}
	if len(missing) > 0 {
		return errors.New("missing required configuration: " + strings.Join(missing, ", "))
	}
	if len(c.Auth.SessionSigningKey) < 32 {
		return errors.New("auth.session_signing_key must be at least 32 bytes")
	}
	if len(c.Auth.CeremonyEncryptionKey) != 32 {
		return errors.New("auth.ceremony_encryption_key must be exactly 32 bytes")
	}
	if len(c.Relay.TicketKey) < 32 {
		return errors.New("relay.ticket_key must be at least 32 bytes")
	}
	if _, err := c.RelayDuration(); err != nil {
		return err
	}
	origin, err := url.Parse(c.Auth.RPOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("auth.rp_origin must be an HTTPS origin without a path")
	}
	if !strings.EqualFold(origin.Hostname(), c.Auth.RPID) {
		return errors.New("auth.rp_id must match auth.rp_origin hostname")
	}
	if c.Auth.SessionDuration() <= 0 {
		return errors.New("auth.session_ttl must be a positive duration")
	}
	if c.Auth.CeremonyDuration() <= 0 {
		return errors.New("auth.ceremony_ttl must be a positive duration")
	}
	return nil
}

func (c Control) RelayDuration() (time.Duration, error) {
	duration, err := time.ParseDuration(c.Relay.TTL())
	if err != nil || duration <= 0 {
		return 0, errors.New("relay.ticket_ttl must be a positive duration")
	}

	return duration, nil
}

func (r Relay) TTL() string {
	if strings.TrimSpace(r.TicketTTL) == "" {
		return "5m"
	}

	return r.TicketTTL
}

func readSecret(path, label string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	return strings.TrimSpace(string(value)), nil
}
