package acl

import (
	"fmt"
	"net/netip"
	"slices"
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
)

type Rule struct {
	ID             string       `json:"id"`
	SourceDeviceID string       `json:"source_device_id"`
	Destination    netip.Prefix `json:"destination"`
	Protocol       Protocol     `json:"protocol"`
	PortFrom       uint16       `json:"port_from"`
	PortTo         uint16       `json:"port_to"`
}

type Snapshot struct {
	Revision      uint64 `json:"revision"`
	DefaultAction Action `json:"default_action"`
	Rules         []Rule `json:"rules"`
}

type Compiler struct{}

func (Compiler) Compile(revision uint64, rules []Rule) (Snapshot, error) {
	compiled := slices.Clone(rules)
	seenIDs := make(map[string]struct{}, len(compiled))
	for index := range compiled {
		rule := &compiled[index]
		if rule.ID == "" || rule.SourceDeviceID == "" || !rule.Destination.IsValid() ||
			rule.Destination.Bits() == 0 {
			return Snapshot{}, fmt.Errorf("rule identity, source, and destination are required")
		}

		if _, exists := seenIDs[rule.ID]; exists {
			return Snapshot{}, fmt.Errorf("rule %s is duplicated", rule.ID)
		}

		seenIDs[rule.ID] = struct{}{}
		rule.Destination = rule.Destination.Masked()
		if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP {
			return Snapshot{}, fmt.Errorf(
				"rule %s has unsupported protocol %q",
				rule.ID,
				rule.Protocol,
			)
		}
		if rule.PortFrom == 0 || rule.PortTo == 0 || rule.PortFrom > rule.PortTo {
			return Snapshot{}, fmt.Errorf("rule %s has invalid port range", rule.ID)
		}
	}

	slices.SortFunc(compiled, func(a, b Rule) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}

		return 0
	})
	return Snapshot{Revision: revision, DefaultAction: ActionDeny, Rules: compiled}, nil
}
