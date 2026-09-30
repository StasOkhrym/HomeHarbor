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

// ipRunner is replaceable only by package tests. Keeping command execution at
// this seam lets Linux CI verify ordering and rollback decisions without
// granting the test process CAP_NET_ADMIN.
var ipRunner = runIP

// sysctlRunner is replaceable only by package tests. Forwarding is not enabled
// by EnsureLinuxInterface; callers must opt into the host-wide setting through
// the gateway configuration explicitly.
var sysctlRunner = runSysctl

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
	// Validate the complete route set before mutating the link. A malformed
	// later route must not leave a partially reconciled interface behind.
	for _, route := range routes {
		if !route.IsValid() || route.Bits() == 0 {
			return errors.New("invalid route prefix")
		}
	}
	if err := ipRunner(ctx, "link", "show", "dev", name); err != nil {
		if err := ipRunner(ctx, "link", "add", "dev", name, "type", "wireguard"); err != nil {
			return fmt.Errorf("create WireGuard interface: %w", err)
		}
	}
	if err := ipRunner(ctx, "address", "replace", overlayAddress, "dev", name); err != nil {
		return fmt.Errorf("assign overlay address: %w", err)
	}
	if err := ipRunner(ctx, "link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("activate WireGuard interface: %w", err)
	}
	for _, route := range routes {
		if err := ipRunner(ctx, "route", "replace", route.String(), "dev", name); err != nil {
			return fmt.Errorf("install route %s: %w", route, err)
		}
	}
	return nil
}

// EnableLinuxForwarding enables the host-wide forwarding switches required by
// a Linux gateway. It is deliberately separate from interface reconciliation:
// creating a tunnel must not silently alter forwarding for other interfaces.
func EnableLinuxForwarding(ctx context.Context) error {
	if err := sysctlRunner(ctx, "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable IPv4 forwarding: %w", err)
	}

	if err := sysctlRunner(ctx, "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return fmt.Errorf("enable IPv6 forwarding: %w", err)
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

func runSysctl(ctx context.Context, args ...string) error {
	command := exec.CommandContext(ctx, "sysctl", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
