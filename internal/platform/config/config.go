package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Control struct {
	Runtime       Runtime         `toml:"runtime"`
	Server        Server          `toml:"server"`
	Database      Database        `toml:"database"`
	Redis         Redis           `toml:"redis"`
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
	Driver       string `toml:"driver"`
	URL          string `toml:"url"`
	Password     string `toml:"password"`
	PasswordFile string `toml:"password_file"`
}

// Redis configures ephemeral security state; secrets are resolved at startup
// and never placed in the URL, which may appear in diagnostic messages.
type Redis struct {
	URL          string `toml:"url"`
	Password     string `toml:"password"`
	PasswordFile string `toml:"password_file"`
}

func (d *Database) validateDriver() error {
	// Omission preserves existing TOML files, not SQL portability guarantees.
	if d.Driver == "" {
		d.Driver = "postgres"
	}

	if d.Driver != "postgres" {
		return errors.New("database.driver must be postgres")
	}

	return nil
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
	PublicURL        string `toml:"public_url"`
	PublicUDPAddress string `toml:"public_udp_address"`
	TicketKey        string `toml:"ticket_key"`
	TicketKeyFile    string `toml:"ticket_key_file"`
	TicketTTL        string `toml:"ticket_ttl"`
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
	Runtime Runtime `toml:"runtime"`
	Server  struct {
		ListenAddress    string `toml:"listen_address"`
		UDPListenAddress string `toml:"udp_listen_address"`
		UDPPortMin       int    `toml:"udp_port_min"`
		UDPPortMax       int    `toml:"udp_port_max"`
		UDPAdvertiseHost string `toml:"udp_advertise_host"`
	} `toml:"server"`
	Security struct {
		TicketKey     string `toml:"ticket_key"`
		TicketKeyFile string `toml:"ticket_key_file"`
		TLSCertFile   string `toml:"tls_cert_file"`
		TLSKeyFile    string `toml:"tls_key_file"`
	} `toml:"security"`
}

// Admin describes the one-shot trusted-companion CLI. It contains operator
// defaults and paths only; the encrypted root key remains in RootKeyFile and
// the passphrase file is opened by the command after changed flags are applied.
type Admin struct {
	Endpoint             string `toml:"endpoint"`
	KeyID                string `toml:"key_id"`
	RootKeyFile          string `toml:"root_key_file"`
	PassphraseFile       string `toml:"passphrase_file"`
	NetworkID            string `toml:"network_id"`
	ProfileID            string `toml:"profile_id"`
	BaseURL              string `toml:"base_url"`
	OverlayPool          string `toml:"overlay_pool"`
	SnapshotManifestFile string `toml:"snapshot_manifest_file"`
	InviteAttemptsFile   string `toml:"invite_attempts_file"`
}

// LoadAdmin reads trusted-companion defaults. The command resolves the selected
// passphrase file after applying explicitly changed flags.
func LoadAdmin(path string) (Admin, error) {
	var cfg Admin

	if _, err := readFileStrict(path, &cfg); err != nil {
		return Admin{}, err
	}

	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://control.example"
	}

	if cfg.KeyID == "" {
		cfg.KeyID = "root-1"
	}

	if cfg.RootKeyFile == "" {
		cfg.RootKeyFile = "state/root-key.age"
	}

	if cfg.InviteAttemptsFile == "" {
		cfg.InviteAttemptsFile = "state/invite-attempts.json"
	}

	return cfg, nil
}

func LoadRelayServer(source Sources) (RelayServer, error) {
	cfg := RelayServer{Runtime: DefaultRuntime(true)}
	cfg.Server.UDPListenAddress = ":51820"

	fileKeys, err := readFileStrict(source.File, &cfg)
	if err != nil {
		return RelayServer{}, fmt.Errorf("decode relay config: %w", err)
	}

	envKeys, flagKeys, err := applySourcesWithBindings(&cfg, source, relayEnvBindings)
	if err != nil {
		return RelayServer{}, err
	}

	if err := selectedSecret(
		&cfg.Security.TicketKey,
		cfg.Security.TicketKeyFile,
		"security.ticket_key",
		"security.ticket_key_file",
		fileKeys,
		envKeys,
		flagKeys,
	); err != nil {
		return RelayServer{}, err
	}

	if strings.TrimSpace(cfg.Server.UDPListenAddress) == "" {
		return RelayServer{}, errors.New("relay udp_listen_address is required")
	}

	if _, err := net.ResolveUDPAddr("udp", cfg.Server.UDPListenAddress); err != nil {
		return RelayServer{}, fmt.Errorf("invalid relay udp_listen_address: %w", err)
	}

	if (cfg.Security.TLSCertFile == "") != (cfg.Security.TLSKeyFile == "") {
		return RelayServer{}, errors.New(
			"relay TLS certificate and key files must be configured together",
		)
	}

	if cfg.Server.UDPPortMin != 0 || cfg.Server.UDPPortMax != 0 {
		if cfg.Server.UDPPortMin < 1 || cfg.Server.UDPPortMax < cfg.Server.UDPPortMin ||
			cfg.Server.UDPPortMax > 65535 {
			return RelayServer{}, errors.New("relay UDP port range must be ordered within 1..65535")
		}
	}

	if cfg.Server.ListenAddress == "" || len(cfg.Security.TicketKey) < 32 {
		return RelayServer{}, errors.New(
			"relay listen_address and a ticket key of at least 32 bytes are required",
		)
	}

	if err := cfg.Runtime.Validate(); err != nil {
		return RelayServer{}, err
	}

	return cfg, nil
}

// LoadDatabase checks the complete control-file schema but resolves only the
// database section. A migration never opens unrelated auth or relay secrets.
func LoadDatabase(source Sources) (Database, error) {
	var cfg Control

	fileKeys, err := readFileStrict(source.File, &cfg)
	if err != nil {
		return Database{}, err
	}

	// Only database fields are available to this role; other valid sections are
	// parsed for schema correctness but their secrets are never resolved.
	databaseOnly := struct {
		Database Database `toml:"database"`
	}{Database: cfg.Database}
	envKeys, flagKeys, err := applySources(&databaseOnly, source)
	if err != nil {
		return Database{}, err
	}

	database := databaseOnly.Database
	if err := selectedSecret(&database.Password, database.PasswordFile,
		"database.password", "database.password_file", fileKeys, envKeys, flagKeys); err != nil {
		return Database{}, err
	}

	if err := validateDatabase(&database); err != nil {
		return Database{}, err
	}

	return database, nil
}

func LoadControl(source Sources) (Control, error) {
	cfg := Control{Runtime: DefaultRuntime(false)}
	fileKeys, err := readFileStrict(source.File, &cfg)
	if err != nil {
		return Control{}, err
	}
	envKeys, flagKeys, err := applySources(&cfg, source)
	if err != nil {
		return Control{}, err
	}
	for _, pair := range []struct {
		target       *string
		path         string
		inline, file string
	}{
		{&cfg.Database.Password, cfg.Database.PasswordFile, "database.password", "database.password_file"},
		{&cfg.Redis.Password, cfg.Redis.PasswordFile, "redis.password", "redis.password_file"},
		{&cfg.Auth.SessionSigningKey, cfg.Auth.SessionSigningKeyFile, "auth.session_signing_key", "auth.session_signing_key_file"},
		{&cfg.Auth.CeremonyEncryptionKey, cfg.Auth.CeremonyEncryptionKeyFile, "auth.ceremony_encryption_key", "auth.ceremony_encryption_key_file"},
		{&cfg.Relay.TicketKey, cfg.Relay.TicketKeyFile, "relay.ticket_key", "relay.ticket_key_file"},
	} {
		if err := selectedSecret(pair.target, pair.path, pair.inline, pair.file,
			fileKeys, envKeys, flagKeys); err != nil {
			return Control{}, err
		}
	}
	if cfg.Redis.URL != "" {
		endpoint, err := url.Parse(cfg.Redis.URL)
		if err != nil || endpoint.Host == "" ||
			(endpoint.Scheme != "redis" && endpoint.Scheme != "rediss") ||
			endpoint.User != nil {
			return Control{}, errors.New(
				"redis.url must be a redis/rediss endpoint without embedded credentials",
			)
		}
	}
	if err := validateDatabase(&cfg.Database); err != nil {
		return Control{}, err
	}
	if cfg.Relay.TicketTTL == "" && (fileKeys["relay.ticket_ttl"] ||
		envKeys["relay.ticket_ttl"] || flagKeys["relay.ticket_ttl"]) {
		return Control{}, errors.New("relay.ticket_ttl must be a positive duration")
	}
	if err := cfg.validate(); err != nil {
		return Control{}, err
	}
	if err := cfg.Runtime.Validate(); err != nil {
		return Control{}, err
	}
	return cfg, nil
}

func (c Control) validate() error {
	if err := c.Database.validateDriver(); err != nil {
		return err
	}
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
		// Without the companion's public key, control would fall back to the
		// legacy role-only relay authorization path and could grant a tunnel
		// without a trusted signed snapshot.
		{"security.root_public_key_file", c.Security.RootPublicKeyFile},
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
	if address := strings.TrimSpace(c.Relay.PublicUDPAddress); address != "" {
		host, port, splitErr := net.SplitHostPort(address)
		portNumber, portErr := strconv.Atoi(port)
		if splitErr != nil || strings.TrimSpace(host) == "" || portErr != nil || portNumber < 1 ||
			portNumber > 65535 {
			return errors.New("relay.public_udp_address must be a host:port with a valid port")
		}
	}
	if _, err := c.RelayDuration(); err != nil {
		return err
	}
	origin, err := url.Parse(c.Auth.RPOrigin)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.Path != "" ||
		origin.RawQuery != "" ||
		origin.Fragment != "" {
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
