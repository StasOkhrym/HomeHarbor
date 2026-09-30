package node

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/agent/nft"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type orderedDNSApplier struct {
	events *[]string
	calls  int
	err    error
}

func (d *orderedDNSApplier) Apply(context.Context, snapshot.NetworkSnapshot) error {
	d.calls++
	*d.events = append(*d.events, "dns")
	if d.calls == 1 {
		return d.err
	}

	return nil
}

func TestGatewayReconcilerCommitsFirewallBeforeDNSAndRetriesDNSOnly(t *testing.T) {
	events := []string{}
	dnsFailure := errors.New("resolver temporarily unavailable")
	dnsApplier := &orderedDNSApplier{events: &events, err: dnsFailure}
	reconciler := NewGatewayReconcilerWithEnsurer("wg0", "gateway", dnsApplier, false, func(context.Context, string, string, []netip.Prefix) error {
		events = append(events, "interface")
		return nil
	})
	nftCalls := 0
	reconciler.policies = nft.NewApplierWithRunner("wg0", nil, func(context.Context, string) error {
		nftCalls++
		events = append(events, "nft")
		return nil
	})
	value := gatewaySnapshotForReconciler()

	if err := reconciler.Apply(context.Background(), value); !errors.Is(err, dnsFailure) {
		t.Fatalf("first Apply() error=%v, want %v", err, dnsFailure)
	}
	if got, want := events, []string{"interface", "nft", "dns"}; !equalStrings(got, want) {
		t.Fatalf("first event order=%v, want=%v", got, want)
	}
	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatalf("retry Apply() error=%v", err)
	}
	if nftCalls != 1 {
		t.Fatalf("nft calls=%d, want one committed policy", nftCalls)
	}
	if got, want := events, []string{"interface", "nft", "dns", "interface", "dns"}; !equalStrings(got, want) {
		t.Fatalf("retry event order=%v, want=%v", got, want)
	}
}

func gatewaySnapshotForReconciler() snapshot.NetworkSnapshot {
	return snapshot.NetworkSnapshot{
		NetworkID: "home",
		Revision:  1,
		Devices: []snapshot.Device{
			{ID: "gateway", Role: "gateway", OverlayAddress: "10.200.0.1/32"},
			{ID: "client", Role: "client", OverlayAddress: "10.200.0.2/32"},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway", Name: "Home"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24", Resolver: "192.168.50.2", DomainSuffix: "home.arpa"}},
		ACL:      []snapshot.ACLRule{{ID: "allow-http", SourceDeviceID: "client", Destination: "192.168.50.2/32", Protocol: "tcp", PortFrom: 8080, PortTo: 8080}},
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}

	return true
}
