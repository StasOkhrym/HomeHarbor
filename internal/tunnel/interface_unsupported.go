//go:build !linux

package tunnel

import (
	"context"
	"errors"
	"net/netip"
)

// EnsureLinuxInterface is intentionally unavailable outside Linux. The
// gateway's kernel route and nftables lifecycle must never silently degrade to
// a best-effort userspace approximation on a developer workstation.
func EnsureLinuxInterface(context.Context, string, string, []netip.Prefix) error {
	return errors.New("linux WireGuard interface lifecycle is only supported on Linux")
}
