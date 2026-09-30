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

	resolver, suffixes, err := prepareDNS(value)
	if err != nil {
		return err
	}
	if !resolver.IsValid() {
		return r.manager.Close(ctx)
	}

	return r.manager.Apply(ctx, resolver, suffixes)
}

// Prepare is read-only: CompositeSnapshotApplier must call it on every owner
// before installing a gateway guard or changing any kernel/resolver state.
func (r *DNSReconciler) Prepare(ctx context.Context, value snapshot.NetworkSnapshot) error {
	if r == nil || r.manager == nil {
		return errors.New("dns reconciler is not configured")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	_, _, err := prepareDNS(value)

	return err
}

func prepareDNS(value snapshot.NetworkSnapshot) (netip.Addr, []string, error) {
	var resolver netip.Addr
	var suffixes []string
	for _, route := range value.Routes {
		if (route.DomainSuffix == "") != (route.Resolver == "") {
			return netip.Addr{}, nil, fmt.Errorf("route %s requires DNS suffix and resolver together", route.ID)
		}
		if route.DomainSuffix == "" {
			continue
		}
		current, err := netip.ParseAddr(route.Resolver)
		if err != nil {
			return netip.Addr{}, nil, fmt.Errorf("route %s has invalid DNS resolver: %w", route.ID, err)
		}
		prefix, err := netip.ParsePrefix(route.Prefix)
		if err != nil || prefix.Bits() == 0 || !prefix.Contains(current) {
			return netip.Addr{}, nil, fmt.Errorf("route %s DNS resolver is outside its non-default prefix", route.ID)
		}
		if resolver.IsValid() && resolver != current {
			return netip.Addr{}, nil, errors.New("snapshot contains multiple split-DNS resolvers")
		}
		resolver = current
		suffixes = append(suffixes, route.DomainSuffix)
	}
	if !resolver.IsValid() {
		return netip.Addr{}, nil, nil
	}
	canonical, err := dns.ValidateSettings(resolver, suffixes)
	return resolver, canonical, err
}
