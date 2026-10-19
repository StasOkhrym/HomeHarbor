package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Sources is a startup snapshot. Flags contains only flags explicitly supplied
// by the caller, keyed by dotted TOML field name.
type Sources struct {
	File  string
	Env   func(string) (string, bool)
	Flags map[string]string
}

type presence map[string]bool

func readFileStrict(path string, target any) (presence, error) {
	set := presence{}
	if path == "" {
		return set, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	meta, err := toml.Decode(string(data), target)
	if err != nil {
		// TOML syntax and conversion errors may quote secret source lines.
		return nil, errors.New("decode config: invalid TOML")
	}

	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("unknown config key: %s", undecoded[0].String())
	}

	for _, key := range meta.Keys() {
		set[key.String()] = true
	}

	return set, nil
}

// envBindings is intentionally explicit: adding a TOML field does not silently
// make it remotely configurable through the process environment.
var envBindings = map[string]string{
	"smtp.enabled":                      "HOMEHARBOR_SMTP_ENABLED",
	"smtp.host":                         "HOMEHARBOR_SMTP_HOST",
	"smtp.port":                         "HOMEHARBOR_SMTP_PORT",
	"smtp.username":                     "HOMEHARBOR_SMTP_USERNAME",
	"smtp.password":                     "HOMEHARBOR_SMTP_PASSWORD",
	"smtp.password_file":                "HOMEHARBOR_SMTP_PASSWORD_FILE",
	"smtp.from":                         "HOMEHARBOR_SMTP_FROM",
	"smtp.mode":                         "HOMEHARBOR_SMTP_MODE",
	"smtp.timeout":                      "HOMEHARBOR_SMTP_TIMEOUT",
	"smtp.ca_file":                      "HOMEHARBOR_SMTP_CA_FILE",
	"server.listen_address":             "HOMEHARBOR_SERVER_LISTEN_ADDRESS",
	"database.url":                      "HOMEHARBOR_DATABASE_URL",
	"database.password":                 "HOMEHARBOR_DATABASE_PASSWORD",
	"database.password_file":            "HOMEHARBOR_DATABASE_PASSWORD_FILE",
	"redis.url":                         "HOMEHARBOR_REDIS_URL",
	"redis.password":                    "HOMEHARBOR_REDIS_PASSWORD",
	"redis.password_file":               "HOMEHARBOR_REDIS_PASSWORD_FILE",
	"auth.session_signing_key":          "HOMEHARBOR_AUTH_SESSION_SIGNING_KEY",
	"auth.session_signing_key_file":     "HOMEHARBOR_AUTH_SESSION_SIGNING_KEY_FILE",
	"auth.ceremony_encryption_key":      "HOMEHARBOR_AUTH_CEREMONY_ENCRYPTION_KEY",
	"auth.ceremony_encryption_key_file": "HOMEHARBOR_AUTH_CEREMONY_ENCRYPTION_KEY_FILE",
	"relay.ticket_key":                  "HOMEHARBOR_RELAY_TICKET_KEY",
	"relay.ticket_key_file":             "HOMEHARBOR_RELAY_TICKET_KEY_FILE",
	"node.state_path":                   "HOMEHARBOR_NODE_STATE_PATH",
	"node.control_url":                  "HOMEHARBOR_NODE_CONTROL_URL",
	"node.enrollment_token_file":        "HOMEHARBOR_NODE_ENROLLMENT_TOKEN_FILE",
	"node.refresh":                      "HOMEHARBOR_NODE_REFRESH",
	"node.name":                         "HOMEHARBOR_NODE_NAME",
	"relay.websocket_url":               "HOMEHARBOR_NODE_RELAY_WEBSOCKET_URL",
	"relay.signed_peers":                "HOMEHARBOR_NODE_RELAY_SIGNED_PEERS",
	"relay.ticket_file":                 "HOMEHARBOR_NODE_RELAY_TICKET_FILE",
	"coordination.url":                  "HOMEHARBOR_NODE_COORDINATION_URL",
}

// The relay process has a different schema from control's relay section.
// Keep its legacy HOMEHARBOR_RELAY_* variables bound to that role only.
var relayEnvBindings = map[string]string{
	"server.listen_address":     "HOMEHARBOR_RELAY_LISTEN_ADDRESS",
	"server.udp_listen_address": "HOMEHARBOR_RELAY_UDP_LISTEN_ADDRESS",
	"server.udp_port_min":       "HOMEHARBOR_RELAY_UDP_PORT_MIN",
	"server.udp_port_max":       "HOMEHARBOR_RELAY_UDP_PORT_MAX",
	"server.udp_advertise_host": "HOMEHARBOR_RELAY_UDP_ADVERTISE_HOST",
	"security.ticket_key":       "HOMEHARBOR_RELAY_TICKET_KEY",
	"security.ticket_key_file":  "HOMEHARBOR_RELAY_TICKET_KEY_FILE",
	"security.tls_cert_file":    "HOMEHARBOR_RELAY_TLS_CERT_FILE",
	"security.tls_key_file":     "HOMEHARBOR_RELAY_TLS_KEY_FILE",
}

func applySources(target any, source Sources) (presence, presence, error) {
	return applySourcesWithBindings(target, source, envBindings)
}

func applySourcesWithBindings(
	target any,
	source Sources,
	bindings map[string]string,
) (presence, presence, error) {
	envKeys, flagKeys := presence{}, presence{}
	lookup := source.Env
	if lookup == nil {
		lookup = os.LookupEnv
	}

	fields := fieldPaths(reflect.ValueOf(target).Elem(), "")
	for _, key := range sortedSourceKeys(bindings) {
		name := bindings[key]
		field, allowed := fields[key]
		if !allowed {
			continue
		}

		if value, ok := lookup(name); ok {
			if err := setScalar(field, value); err != nil {
				return nil, nil, fmt.Errorf("invalid environment value for %s", key)
			}

			envKeys[key] = true
		}
	}

	for _, key := range sortedSourceKeys(source.Flags) {
		value := source.Flags[key]
		field, ok := fields[key]
		if !ok {
			return nil, nil, fmt.Errorf("unknown config flag: %s", key)
		}

		if err := setScalar(field, value); err != nil {
			return nil, nil, fmt.Errorf("invalid flag value for %s", key)
		}

		flagKeys[key] = true
	}

	return envKeys, flagKeys, nil
}

func sortedSourceKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)
	return keys
}

func fieldPaths(value reflect.Value, prefix string) map[string]reflect.Value {
	fields := map[string]reflect.Value{}
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("toml"), ",")[0]
		if !field.IsExported() || name == "-" {
			continue
		}

		if name == "" {
			name = strings.ToLower(field.Name)
		}

		key := name
		if prefix != "" {
			key = prefix + "." + name
		}

		item := value.Field(i)
		if item.Kind() == reflect.Struct && item.Type() != reflect.TypeOf(time.Duration(0)) {
			for nested, nestedItem := range fieldPaths(item, key) {
				fields[nested] = nestedItem
			}

			continue
		}

		fields[key] = item
	}

	return fields
}

func setScalar(field reflect.Value, raw string) error {
	if field.Type() == reflect.TypeOf(time.Duration(0)) {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}

		field.SetInt(int64(value))
		return nil
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
	case reflect.Bool:
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}

		field.SetBool(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := strconv.ParseInt(raw, 10, field.Type().Bits())
		if err != nil {
			return err
		}

		field.SetInt(value)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, err := strconv.ParseUint(raw, 10, field.Type().Bits())
		if err != nil {
			return err
		}

		field.SetUint(value)
	case reflect.Slice:
		if field.Type().Elem().Kind() != reflect.String {
			return errors.New("unsupported slice")
		}

		if raw == "" {
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
		} else {
			field.Set(reflect.ValueOf(strings.Split(raw, ",")))
		}
	default:
		return errors.New("unsupported config field")
	}

	return nil
}

func selectedSecret(
	target *string,
	filePath string,
	inlineKey, fileKey string,
	sets ...presence,
) error {
	for _, source := range sets {
		if source[inlineKey] && source[fileKey] {
			return fmt.Errorf("%s and %s conflict in one source", inlineKey, fileKey)
		}
	}

	selected := -1
	fromFile := false
	for i, source := range sets {
		if source[inlineKey] || source[fileKey] {
			selected = i
			fromFile = source[fileKey]
		}
	}

	if selected < 0 || !fromFile {
		return nil
	}
	if filePath == "" {
		*target = ""
		return nil
	}

	value, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read %s: file unavailable", fileKey)
	}

	*target = strings.TrimSpace(string(value))
	if *target == "" {
		return fmt.Errorf("%s file is empty", fileKey)
	}

	return nil
}

func validateDatabase(database *Database) error {
	if err := database.validateDriver(); err != nil {
		return err
	}

	if strings.TrimSpace(database.URL) == "" {
		return errors.New("database.url is required")
	}

	parsed, err := url.Parse(database.URL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") ||
		parsed.Host == "" {
		return errors.New("database.url must be a PostgreSQL URL")
	}

	return nil
}
