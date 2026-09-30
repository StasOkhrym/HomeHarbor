package nft

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

func TestCompileScopesDefaultDenyAndExplicitAllows(t *testing.T) {
	script, err := Compile("gt0", map[string]netip.Prefix{"client-1": netip.MustParsePrefix("100.64.0.2/32")}, policy.Snapshot{Revision: 9, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{ID: "ssh", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.0.0.10/32"), Protocol: policy.ProtocolTCP, PortFrom: 22, PortTo: 22}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet go_tunnels", "policy accept", "iifname \"gt0\" drop", "oifname \"gt0\" drop", "hook input", "ip saddr 100.64.0.2/32 ip daddr 10.0.0.10/32 tcp dport 22 accept", "revision=9", "ct original ip saddr 100.64.0.2/32", "ct original ip daddr 10.0.0.10/32", "ct original proto-dst 22"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "policy drop") || strings.Contains(script, "ct state established,related accept") {
		t.Fatalf("global deny or established-flow ACL bypass:\n%s", script)
	}
	if strings.Contains(script, "flush table inet go_tunnels") {
		t.Fatalf("Compile() emitted a state-dependent flush before table existence is known:\n%s", script)
	}
}

func TestCompileRejectsMalformedACLAndAmbiguousIdentity(t *testing.T) {
	valid := policy.Rule{ID: "http", SourceDeviceID: "client", Destination: netip.MustParsePrefix("192.168.50.2/32"), Protocol: policy.ProtocolTCP, PortFrom: 80, PortTo: 80}
	for _, change := range []struct {
		name   string
		mutate func(*policy.Rule, map[string]netip.Prefix)
	}{
		{"protocol injection", func(r *policy.Rule, _ map[string]netip.Prefix) { r.Protocol = "tcp accept;" }},
		{"default destination", func(r *policy.Rule, _ map[string]netip.Prefix) { r.Destination = netip.MustParsePrefix("0.0.0.0/0") }},
		{"zero port", func(r *policy.Rule, _ map[string]netip.Prefix) { r.PortFrom = 0 }},
		{"reversed ports", func(r *policy.Rule, _ map[string]netip.Prefix) { r.PortTo = 1 }},
		{"subnet identity", func(_ *policy.Rule, p map[string]netip.Prefix) { p["client"] = netip.MustParsePrefix("100.64.0.2/24") }},
		{"duplicate address", func(_ *policy.Rule, p map[string]netip.Prefix) { p["other"] = p["client"] }},
	} {
		t.Run(change.name, func(t *testing.T) {
			rule := valid
			peers := map[string]netip.Prefix{"client": netip.MustParsePrefix("100.64.0.2/32")}
			change.mutate(&rule, peers)
			if script, err := Compile("wg0", peers, policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{rule}}); err == nil || script != "" {
				t.Fatalf("malformed policy accepted: err=%v script=%s", err, script)
			}
		})
	}
}

func TestCompileRejectsNonDenySnapshot(t *testing.T) {
	if _, err := Compile("gt0", nil, policy.Snapshot{DefaultAction: policy.ActionAllow}); err == nil {
		t.Fatal("Compile() error=nil")
	}
}
