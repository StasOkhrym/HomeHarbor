package nft

import (
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	"net/netip"
	"strings"
	"testing"
)

func TestCompileUsesDefaultDropAndExplicitAllows(t *testing.T) {
	script, err := Compile("gt0", map[string]netip.Prefix{"client-1": netip.MustParsePrefix("100.64.0.2/32")}, policy.Snapshot{Revision: 9, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{ID: "ssh", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.0.0.10/32"), Protocol: policy.ProtocolTCP, PortFrom: 22, PortTo: 22}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"table inet go_tunnels", "policy drop", "ip saddr 100.64.0.2/32 ip daddr 10.0.0.10/32 tcp dport 22 accept", "revision=9"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}
func TestCompileRejectsNonDenySnapshot(t *testing.T) {
	if _, err := Compile("gt0", nil, policy.Snapshot{DefaultAction: policy.ActionAllow}); err == nil {
		t.Fatal("Compile() error=nil")
	}
}
