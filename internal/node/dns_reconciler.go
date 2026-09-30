package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/sokhrym/go-tunnels/internal/agent/dns"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

// DNSReconciler turns only approved snapshot routes with DNS metadata into
// route-only systemd-resolved domains. Routes without a suffix never alter the
// host resolver, and mixed resolver addresses are rejected rather than split
// traffic unpredictably across LAN resolvers.
type DNSReconciler struct {
	manager *dns.Manager
}

func NewDNSReconciler(manager *dns.Manager) *DNSReconciler { return &DNSReconciler{manager: manager} }

func (r *DNSReconciler) Apply(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.manager == nil {
		return errors.New("dns reconciler is not configured")
	}
	var resolver netip.Addr
	var suffixes []string
	for _, route := range value.Routes {
		if route.DomainSuffix == "" || route.Resolver == "" {
			continue
		}
		current, err := netip.ParseAddr(route.Resolver)
		if err != nil {
			return fmt.Errorf("route %s has invalid DNS resolver: %w", route.ID, err)
		}
		if resolver.IsValid() && resolver != current {
			return errors.New("snapshot contains multiple split-DNS resolvers")
		}
		resolver = current
		suffixes = append(suffixes, route.DomainSuffix)
	}
	if !resolver.IsValid() {
		return r.manager.Close(ctx)
	}
	return r.manager.Apply(ctx, resolver, suffixes)
}
