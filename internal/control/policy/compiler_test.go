package policy

import (
	"net/netip"
	"testing"
)

func TestCompilerDefaultsToDenyAndSortsRules(t *testing.T) {
	compiler := Compiler{}
	snapshot, err := compiler.Compile(7, []Rule{
		{ID: "b", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.10.0.0/16"), Protocol: ProtocolTCP, PortFrom: 443, PortTo: 443},
		{ID: "a", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.0.0.10/32"), Protocol: ProtocolTCP, PortFrom: 22, PortTo: 22},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if snapshot.DefaultAction != ActionDeny {
		t.Fatalf("default action = %q", snapshot.DefaultAction)
	}
	if snapshot.Revision != 7 || len(snapshot.Rules) != 2 || snapshot.Rules[0].ID != "a" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
}

func TestCompilerRejectsInvalidPortRange(t *testing.T) {
	_, err := (Compiler{}).Compile(1, []Rule{{
		ID: "bad", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.0.0.0/8"), Protocol: ProtocolTCP, PortFrom: 443, PortTo: 80,
	}})
	if err == nil {
		t.Fatal("Compile() error = nil, want invalid port range")
	}
}

func TestCompilerRejectsDefaultDestination(t *testing.T) {
	_, err := (Compiler{}).Compile(1, []Rule{{
		ID: "internet", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("0.0.0.0/0"), Protocol: ProtocolTCP, PortFrom: 443, PortTo: 443,
	}})
	if err == nil {
		t.Fatal("Compile() accepted a default destination")
	}
}

func TestCompilerRejectsDuplicateRuleIDs(t *testing.T) {
	_, err := (Compiler{}).Compile(1, []Rule{
		{ID: "same", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.0.0.0/8"), Protocol: ProtocolTCP, PortFrom: 443, PortTo: 443},
		{ID: "same", SourceDeviceID: "client-1", Destination: netip.MustParsePrefix("10.1.0.0/16"), Protocol: ProtocolTCP, PortFrom: 22, PortTo: 22},
	})
	if err == nil {
		t.Fatal("Compile() accepted duplicate rule IDs")
	}
}
