//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// EnsureLinuxInterface creates or reuses a WireGuard link and installs its
// overlay address and routes. Each command is idempotent so reconnects can
// reconcile state without tearing down an interface that carries traffic.
func EnsureLinuxInterface(ctx context.Context, name, overlayAddress string, routes []netip.Prefix) error {
	if !interfaceNamePattern.MatchString(name) {
		return errors.New("invalid Linux interface name")
	}
	if overlayAddress == "" {
		return errors.New("overlay address is required")
	}
	if _, err := netip.ParsePrefix(overlayAddress); err != nil {
		return fmt.Errorf("invalid overlay address: %w", err)
	}
	if err := runIP(ctx, "link", "show", "dev", name); err != nil {
		if err := runIP(ctx, "link", "add", "dev", name, "type", "wireguard"); err != nil {
			return fmt.Errorf("create WireGuard interface: %w", err)
		}
	}
	if err := runIP(ctx, "address", "replace", overlayAddress, "dev", name); err != nil {
		return fmt.Errorf("assign overlay address: %w", err)
	}
	if err := runIP(ctx, "link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("activate WireGuard interface: %w", err)
	}
	for _, route := range routes {
		if !route.IsValid() {
			return errors.New("invalid route prefix")
		}
		if err := runIP(ctx, "route", "replace", route.String(), "dev", name); err != nil {
			return fmt.Errorf("install route %s: %w", route, err)
		}
	}
	return nil
}

func runIP(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "ip", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
