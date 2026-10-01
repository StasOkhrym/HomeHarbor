package node

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
)

// routeOwnership tracks only prefixes this reconciler attempted to install
// on its tunnel. Never flush a host routing table: other managers own LAN,
// default and unrelated routes. Failed adds remain tracked so a later revoke
// can remove partially applied state. The gateway guard covers this interval.
type routeOwnership struct {
	installed map[netip.Prefix]struct{}
	run       func(context.Context, ...string) error
}

func newRouteOwnership() routeOwnership {
	return routeOwnership{installed: make(map[netip.Prefix]struct{}), run: runOwnedIP}
}

func (r *routeOwnership) reconcile(
	ctx context.Context,
	link string,
	desired []netip.Prefix,
	install func() error,
) error {
	wanted := make(map[netip.Prefix]struct{}, len(desired))
	for _, prefix := range desired {
		wanted[prefix.Masked()] = struct{}{}
	}

	removed := make([]netip.Prefix, 0)
	for prefix := range r.installed {
		if _, ok := wanted[prefix]; !ok {
			removed = append(removed, prefix)
		}
	}

	slices.SortFunc(
		removed,
		func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) },
	)
	for _, prefix := range removed {
		if err := r.run(ctx, "route", "del", prefix.String(), "dev", link); err != nil {
			return fmt.Errorf("remove revoked tunnel route %s: %w", prefix, err)
		}

		delete(r.installed, prefix)
	}

	for prefix := range wanted {
		r.installed[prefix] = struct{}{}
	}

	return install()
}

func runOwnedIP(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	// Deletion is idempotent, including a partial ensure that never reached
	// its route add. Every other error keeps ownership for the next retry.
	if err != nil && len(args) > 1 && args[1] == "del" &&
		(strings.Contains(string(output), "No such process") || strings.Contains(string(output), "Cannot find device")) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ip: %w (%s)", err, strings.TrimSpace(string(output)))
	}

	return nil
}
