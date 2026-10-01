package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

func Compile(interfaceName string, peerAddresses map[string]netip.Prefix, snapshot policy.Snapshot) (string, error) {
	if !interfaceNamePattern.MatchString(interfaceName) {
		return "", errors.New("invalid tunnel interface name")
	}
	if snapshot.DefaultAction != policy.ActionDeny {
		return "", errors.New("only default-deny snapshots are supported")
	}
	seenAddresses := make(map[netip.Addr]string, len(peerAddresses))
	for id, prefix := range peerAddresses {
		// WireGuard binds a key to exactly one overlay host. A subnet or
		// duplicate identity here would let one peer impersonate another ACL source.
		if id == "" || !prefix.IsValid() || prefix.Bits() != prefix.Addr().BitLen() || prefix.Addr().IsUnspecified() ||
			prefix.Addr().IsMulticast() ||
			prefix.Addr().Is4In6() {
			return "", fmt.Errorf("device %s requires a concrete overlay host prefix", id)
		}
		if previous, ok := seenAddresses[prefix.Addr()]; ok {
			return "", fmt.Errorf("devices %s and %s share an overlay address", previous, id)
		}
		seenAddresses[prefix.Addr()] = id
	}
	validated, err := (policy.Compiler{}).Compile(snapshot.Revision, snapshot.Rules)
	if err != nil {
		return "", err
	}
	// Emit a complete table instead of incremental mutations. Applying this
	// script with `nft -f` swaps one validated policy revision atomically.
	var b strings.Builder
	// This table owns only decrypted traffic on this interface. Other host
	// firewall owners retain their own hooks; an accept here cannot override
	// their drops. Gateway-local services are a separate default-deny boundary.
	fmt.Fprintf(
		&b,
		"# go-tunnels policy revision=%d\ntable inet go_tunnels {\n  chain input {\n    type filter hook input priority -10; policy accept;\n    iifname %q drop\n  }\n  chain forward {\n    type filter hook forward priority -10; policy accept;\n",
		snapshot.Revision,
		interfaceName,
	)
	for _, rule := range validated.Rules {
		source, ok := peerAddresses[rule.SourceDeviceID]
		if !ok || !source.IsValid() {
			return "", fmt.Errorf("missing tunnel address for device %s", rule.SourceDeviceID)
		}
		family := "ip"
		if source.Addr().Is6() {
			family = "ip6"
		}
		destinationFamily := "ip"
		if rule.Destination.Addr().Is6() {
			destinationFamily = "ip6"
		}
		if family != destinationFamily {
			return "", fmt.Errorf("address family mismatch in rule %s", rule.ID)
		}
		fmt.Fprintf(
			&b,
			"    iifname %q %s saddr %s %s daddr %s %s dport %d",
			interfaceName,
			family,
			source,
			destinationFamily,
			rule.Destination,
			rule.Protocol,
			rule.PortFrom,
		)
		if rule.PortTo != rule.PortFrom {
			fmt.Fprintf(&b, "-%d", rule.PortTo)
		}
		fmt.Fprintf(&b, " accept comment %q\n", "go-tunnels:"+rule.ID)
		// Established is evidence of a reply, never authorization. Recheck
		// the CURRENT ACL against conntrack's original tuple on every reply.
		// No broad related acceptance: ICMP helpers must not open another path.
		fmt.Fprintf(
			&b,
			"    oifname %q ct direction reply ct state established meta l4proto %s ct original %s saddr %s ct original %s daddr %s ct original proto-dst %d",
			interfaceName,
			rule.Protocol,
			family,
			source,
			destinationFamily,
			rule.Destination,
			rule.PortFrom,
		)
		if rule.PortTo != rule.PortFrom {
			fmt.Fprintf(&b, "-%d", rule.PortTo)
		}
		fmt.Fprintf(&b, " accept comment %q\n", "go-tunnels:reply:"+rule.ID)
	}
	fmt.Fprintf(&b, "    iifname %q drop\n    oifname %q drop\n  }\n}\n", interfaceName, interfaceName)
	return b.String(), nil
}
