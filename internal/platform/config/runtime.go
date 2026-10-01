package config

import (
	"fmt"
	"time"
)

// Runtime holds startup-only operational limits. Protocol/key sizes and signed
// policy invariants are deliberately not configurable through this structure.
type Runtime struct {
	HTTPHeaderTimeout      time.Duration `toml:"http_header_timeout"`
	HTTPReadTimeout        time.Duration `toml:"http_read_timeout"`
	HTTPWriteTimeout       time.Duration `toml:"http_write_timeout"`
	HTTPIdleTimeout        time.Duration `toml:"http_idle_timeout"`
	ShutdownTimeout        time.Duration `toml:"shutdown_timeout"`
	RedisTimeout           time.Duration `toml:"redis_timeout"`
	OperationTimeout       time.Duration `toml:"operation_timeout"`
	CleanupTimeout         time.Duration `toml:"cleanup_timeout"`
	ClaimTTL               time.Duration `toml:"claim_ttl"`
	CompanionTTL           time.Duration `toml:"companion_ttl"`
	CredentialTTL          time.Duration `toml:"credential_ttl"`
	AuthPerMinute          int           `toml:"auth_per_minute"`
	OnboardingPerMinute    int           `toml:"onboarding_per_minute"`
	APIPerMinute           int           `toml:"api_per_minute"`
	RelayBindTimeout       time.Duration `toml:"relay_bind_timeout"`
	RelayIdleTimeout       time.Duration `toml:"relay_idle_timeout"`
	RelayMaxPeers          int           `toml:"relay_max_peers"`
	RelayMaxPeersPerDevice int           `toml:"relay_max_peers_per_device"`
	RelayMaxAdmissions     int           `toml:"relay_max_admissions"`
}

// DefaultRuntime seeds decoding before TOML is applied. Omitted keys retain
// defaults; explicit zero overwrites them and is rejected by Validate.
func DefaultRuntime(relay bool) Runtime {
	r := Runtime{
		HTTPHeaderTimeout:      5 * time.Second,
		HTTPReadTimeout:        15 * time.Second,
		HTTPWriteTimeout:       30 * time.Second,
		HTTPIdleTimeout:        time.Minute,
		ShutdownTimeout:        10 * time.Second,
		RedisTimeout:           time.Second,
		OperationTimeout:       30 * time.Second,
		CleanupTimeout:         5 * time.Second,
		ClaimTTL:               2 * time.Minute,
		CompanionTTL:           time.Minute,
		CredentialTTL:          15 * time.Minute,
		AuthPerMinute:          5,
		OnboardingPerMinute:    10,
		APIPerMinute:           120,
		RelayBindTimeout:       10 * time.Second,
		RelayIdleTimeout:       2 * time.Minute,
		RelayMaxPeers:          4096,
		RelayMaxPeersPerDevice: 8,
		RelayMaxAdmissions:     16384,
	}
	if relay {
		r.HTTPReadTimeout = 30 * time.Second
	}

	return r
}

// Validate rejects unbounded or incompatible limits before any listener opens.
func (r Runtime) Validate() error {
	for _, field := range []struct {
		name            string
		value, min, max time.Duration
	}{
		{"http_header_timeout", r.HTTPHeaderTimeout, time.Second, 5 * time.Minute},
		{"http_read_timeout", r.HTTPReadTimeout, time.Second, 5 * time.Minute},
		{"http_write_timeout", r.HTTPWriteTimeout, time.Second, 5 * time.Minute},
		{"http_idle_timeout", r.HTTPIdleTimeout, time.Second, 5 * time.Minute},
		{"shutdown_timeout", r.ShutdownTimeout, time.Second, time.Minute},
		{"redis_timeout", r.RedisTimeout, 50 * time.Millisecond, 10 * time.Second},
		{"operation_timeout", r.OperationTimeout, time.Second, 5 * time.Minute},
		{"cleanup_timeout", r.CleanupTimeout, time.Second, time.Minute},
		{"claim_ttl", r.ClaimTTL, time.Second, 2 * time.Minute},
		{"companion_ttl", r.CompanionTTL, time.Second, time.Minute},
		{"credential_ttl", r.CredentialTTL, time.Minute, 15 * time.Minute},
		{"relay_bind_timeout", r.RelayBindTimeout, time.Second, 30 * time.Second},
		{"relay_idle_timeout", r.RelayIdleTimeout, 15 * time.Second, 30 * time.Minute},
	} {
		if field.value < field.min || field.value > field.max {
			return fmt.Errorf("runtime.%s must be within %s..%s", field.name, field.min, field.max)
		}
	}

	for _, field := range []struct {
		name            string
		value, min, max int
	}{
		{"auth_per_minute", r.AuthPerMinute, 1, 30},
		{"onboarding_per_minute", r.OnboardingPerMinute, 1, 60},
		{"api_per_minute", r.APIPerMinute, 1, 600},
		{"relay_max_peers", r.RelayMaxPeers, 1, 65536},
		{"relay_max_peers_per_device", r.RelayMaxPeersPerDevice, 1, 64},
		{"relay_max_admissions", r.RelayMaxAdmissions, r.RelayMaxPeers, 262144},
	} {
		if field.value < field.min || field.value > field.max {
			return fmt.Errorf("runtime.%s must be within %d..%d", field.name, field.min, field.max)
		}
	}

	return nil
}
