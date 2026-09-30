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
	// Emit a complete table instead of incremental mutations. Applying this
	// script with `nft -f` swaps one validated policy revision atomically.
	var b strings.Builder
	fmt.Fprintf(&b, "# go-tunnels policy revision=%d\ntable inet go_tunnels {\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n    ct state established,related accept\n", snapshot.Revision)
	for _, rule := range snapshot.Rules {
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
		fmt.Fprintf(&b, "    iifname %q %s saddr %s %s daddr %s %s dport %d", interfaceName, family, source, destinationFamily, rule.Destination, rule.Protocol, rule.PortFrom)
		if rule.PortTo != rule.PortFrom {
			fmt.Fprintf(&b, "-%d", rule.PortTo)
		}
		fmt.Fprintf(&b, " accept comment %q\n", "go-tunnels:"+rule.ID)
	}
	b.WriteString("  }\n}\n")
	return b.String(), nil
}
