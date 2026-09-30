package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync"
)

type commandRunner func(context.Context, ...string) error

// Manager owns split-DNS settings for one tunnel link. It configures only
// route-only domains (~suffix) and always reverts the link on a failed update
// or Close, leaving the host's normal resolver untouched.
type Manager struct {
	mu       sync.Mutex
	link     string
	run      commandRunner
	active   bool
	resolver netip.Addr
	suffixes []string
}

func NewManager(link string) (*Manager, error) {
	if err := validateLink(link); err != nil {
		return nil, err
	}

	return &Manager{link: link, run: runResolvectl}, nil
}

// Apply replaces the link's private resolver settings. A failure after the
// first command invokes revert before returning, so callers do not inherit a
// partially configured resolver after a stale snapshot.
func (m *Manager) Apply(ctx context.Context, resolver netip.Addr, suffixes []string) error {
	if m == nil {
		return errors.New("dns manager is nil")
	}
	if !resolver.IsValid() || resolver.IsUnspecified() {
		return errors.New("a concrete DNS resolver address is required")
	}
	canonical, err := canonicalSuffixes(suffixes)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previousActive := m.active
	previousResolver := m.resolver
	previousSuffixes := slices.Clone(m.suffixes)
	if err := m.run(ctx, "revert", m.link); err != nil {
		return fmt.Errorf("reset split DNS link: %w", err)
	}
	if err := m.applySettings(ctx, resolver, canonical); err != nil {
		// Reapply the previous valid settings when an update fails. A bare
		// revert would restore the host resolver but silently break existing
		// private-name resolution during a transient command failure.
		if previousActive {
			if restoreErr := m.restoreSettings(previousResolver, previousSuffixes); restoreErr != nil {
				m.active = false
				m.resolver = netip.Addr{}
				m.suffixes = nil
			}
		} else {
			_ = m.run(context.Background(), "revert", m.link)
		}
		return err
	}
	m.active = true
	m.resolver = resolver
	m.suffixes = canonical
	return nil
}

func (m *Manager) applySettings(ctx context.Context, resolver netip.Addr, suffixes []string) error {
	if err := m.run(ctx, "dns", m.link, resolver.String()); err != nil {
		return fmt.Errorf("set split DNS resolver: %w", err)
	}
	for _, suffix := range suffixes {
		if err := m.run(ctx, "domain", m.link, "~"+suffix); err != nil {
			return fmt.Errorf("set split DNS suffix %s: %w", suffix, err)
		}
	}
	if err := m.run(ctx, "default-route", m.link, "false"); err != nil {
		return fmt.Errorf("disable split DNS default route: %w", err)
	}
	return nil
}

func (m *Manager) restoreSettings(resolver netip.Addr, suffixes []string) error {
	ctx := context.Background()
	if err := m.run(ctx, "revert", m.link); err != nil {
		return err
	}
	return m.applySettings(ctx, resolver, suffixes)
}

// Close restores the system resolver state for the managed link.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	if err := m.run(ctx, "revert", m.link); err != nil {
		return fmt.Errorf("restore system DNS: %w", err)
	}
	m.active = false
	m.resolver = netip.Addr{}
	m.suffixes = nil
	return nil
}

func canonicalSuffixes(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
		if value == "" || strings.ContainsAny(value, "/\\:,@;\"'") || strings.HasPrefix(value, ".") || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
			return nil, fmt.Errorf("invalid DNS suffix %q", value)
		}
		for _, label := range strings.Split(value, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, fmt.Errorf("invalid DNS suffix %q", value)
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
					return nil, fmt.Errorf("invalid DNS suffix %q", value)
				}
			}
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	slices.Sort(result)
	return result, nil
}

func validateLink(link string) error {
	if link == "" || len(link) > 15 || strings.ContainsAny(link, " /\\") {
		return errors.New("invalid DNS link name")
	}

	return nil
}

func runResolvectl(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "resolvectl", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("resolvectl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
