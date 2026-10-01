package node

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/agent/nft"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type orderedDNSApplier struct {
	events *[]string
	calls  int
	err    error
}

func (*orderedDNSApplier) Prepare(context.Context, snapshot.NetworkSnapshot) error { return nil }

// This is the parent's multi-owner integration contract. The firewall must
// stay closed after ApplyPrepared until the other owners have also succeeded.
type stagedGateway interface {
	Prepare(context.Context, snapshot.NetworkSnapshot) error
	Guard(context.Context, snapshot.NetworkSnapshot) error
	ApplyPrepared(context.Context, snapshot.NetworkSnapshot) error
	Commit(context.Context, snapshot.NetworkSnapshot) error
	Revision() uint64
}

func TestGatewayStagedCommitKeepsGuardAcrossOtherOwnerFailure(t *testing.T) {
	var live string
	r := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		nil,
		false,
		func(context.Context, string, string, []netip.Prefix) error { return nil },
	)
	r.policies = nft.NewApplierWithRunner("wg0", nil, func(_ context.Context, s string) error { live = s; return nil })
	stage, ok := any(r).(stagedGateway)
	if !ok {
		t.Fatal("gateway lacks staged parent integration API")
	}
	ctx := context.Background()
	v := gatewaySnapshotForReconciler()
	for attempt := 0; attempt < 2; attempt++ {
		if err := stage.Prepare(ctx, v); err != nil {
			t.Fatal(err)
		}
		if err := stage.Guard(ctx, v); err != nil {
			t.Fatal(err)
		}
		if err := stage.ApplyPrepared(ctx, v); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(live, " accept comment") || !strings.Contains(live, "iifname \"wg0\" drop") ||
			stage.Revision() != 0 {
			t.Fatalf("partial revision exposed traffic: rev=%d script=%s", stage.Revision(), live)
		}
		// First attempt models a later WireGuard failure: parent returns
		// without Commit and retries the same desired revision.
	}
	if err := stage.Commit(ctx, v); err != nil {
		t.Fatal(err)
	}
	if stage.Revision() != 1 || !strings.Contains(live, "tcp dport 8080 accept") {
		t.Fatalf("commit did not release matching policy: rev=%d script=%s", stage.Revision(), live)
	}
}

func TestGatewayGuardBeforeEnsureFailureAndRevokedGateway(t *testing.T) {
	var live string
	fail := true
	r := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		nil,
		false,
		func(context.Context, string, string, []netip.Prefix) error {
			if !strings.Contains(live, "iifname \"wg0\" drop") || strings.Contains(live, " accept comment") {
				t.Error("interface opened without deny guard")
			}
			if fail {
				return errors.New("route failure")
			}
			return nil
		},
	)
	r.policies = nft.NewApplierWithRunner("wg0", nil, func(_ context.Context, s string) error { live = s; return nil })
	r.routes.run = func(context.Context, ...string) error { return nil }
	v := gatewaySnapshotForReconciler()
	if err := r.Apply(context.Background(), v); err == nil {
		t.Fatal("expected route failure")
	}
	if strings.Contains(live, " accept comment") {
		t.Fatal("partial apply left tunnel open")
	}
	fail = false
	if err := r.Apply(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	v.Revision = 2
	v.Gateways = nil
	v.Routes = nil
	v.ACL = nil
	if err := r.Apply(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(live, " accept comment") {
		t.Fatal("gateway removal retained ACL")
	}
}

func (d *orderedDNSApplier) Apply(context.Context, snapshot.NetworkSnapshot) error {
	d.calls++
	*d.events = append(*d.events, "dns")
	if d.calls == 1 {
		return d.err
	}

	return nil
}

func TestGatewayReconcilerGuardsBeforeInterfaceAndRetriesSameRevision(t *testing.T) {
	events := []string{}
	dnsFailure := errors.New("resolver temporarily unavailable")
	dnsApplier := &orderedDNSApplier{events: &events, err: dnsFailure}
	reconciler := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		dnsApplier,
		false,
		func(context.Context, string, string, []netip.Prefix) error {
			events = append(events, "interface")
			return nil
		},
	)
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

	if got, want := events, []string{"nft", "interface", "dns"}; !equalStrings(got, want) {
		t.Fatalf("first event order=%v, want=%v", got, want)
	}

	if reconciler.policies.Revision() != 0 {
		t.Fatal("firewall revision advanced despite failed DNS")
	}

	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatalf("retry Apply() error=%v", err)
	}

	if nftCalls != 3 {
		t.Fatalf("nft calls=%d, want guard, retry guard, commit", nftCalls)
	}

	if got, want := events, []string{
		"nft",
		"interface",
		"dns",
		"nft",
		"interface",
		"dns",
		"nft",
	}; !equalStrings(
		got,
		want,
	) {
		t.Fatalf("retry event order=%v, want=%v", got, want)
	}
}

func TestGatewayMalformedStateDoesNotMutate(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*snapshot.NetworkSnapshot)
	}{
		{"ACL destination", func(v *snapshot.NetworkSnapshot) { v.ACL[0].Destination = "bad" }},
		{"ACL protocol", func(v *snapshot.NetworkSnapshot) { v.ACL[0].Protocol = "icmp" }},
		{"DNS suffix", func(v *snapshot.NetworkSnapshot) { v.Routes[0].DomainSuffix = "~." }},
		{"DNS resolver", func(v *snapshot.NetworkSnapshot) { v.Routes[0].Resolver = "0.0.0.0" }},
		{"default route", func(v *snapshot.NetworkSnapshot) { v.Routes[0].Prefix = "0.0.0.0/0" }},
		{"duplicate device", func(v *snapshot.NetworkSnapshot) { v.Devices = append(v.Devices, v.Devices[1]) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			calls := 0
			r := NewGatewayReconcilerWithEnsurer(
				"wg0",
				"gateway",
				nil,
				false,
				func(context.Context, string, string, []netip.Prefix) error { calls++; return nil },
			)
			r.policies = nft.NewApplierWithRunner(
				"wg0",
				nil,
				func(context.Context, string) error { calls++; return nil },
			)

			v := gatewaySnapshotForReconciler()

			change.mutate(&v)

			if err := r.Apply(context.Background(), v); err == nil || calls != 0 {
				t.Fatalf("malformed snapshot: err=%v mutation calls=%d", err, calls)
			}
		})
	}
}

func TestGatewayFinalFirewallFailureLeavesGuardAndRetries(t *testing.T) {
	var live string
	commitFailure := true
	r := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		nil,
		false,
		func(context.Context, string, string, []netip.Prefix) error { return nil },
	)
	r.policies = nft.NewApplierWithRunner("wg0", nil, func(_ context.Context, s string) error {
		if commitFailure && strings.Contains(s, " accept comment") {
			return errors.New("nft commit failed")
		}
		live = s
		return nil
	})
	v := gatewaySnapshotForReconciler()
	if err := r.Apply(context.Background(), v); err == nil {
		t.Fatal("expected commit failure")
	}
	if r.Revision() != 0 || r.policies.Revision() != 0 || strings.Contains(live, " accept comment") {
		t.Fatalf("commit failure exposed partial state: %s", live)
	}
	commitFailure = false
	if err := r.Apply(context.Background(), v); err != nil {
		t.Fatal(err)
	}
	if r.Revision() != 1 {
		t.Fatal("same desired revision did not converge")
	}
	v.Routes[0].DomainSuffix = "other.home.arpa"
	before := live
	if err := r.Apply(context.Background(), v); err == nil || live != before {
		t.Fatal("changed metadata at committed revision mutated live state")
	}
}

func TestClientPrepareRejectsMissingLocalBeforeOtherOwners(t *testing.T) {
	r := NewClientReconcilerWithEnsurer("wg0", "client", func(context.Context, string, string, []netip.Prefix) error {
		t.Fatal("prepare mutated interface")
		return nil
	})
	if err := r.Prepare(context.Background(), snapshot.NetworkSnapshot{}); err == nil {
		t.Fatal("Prepare accepted missing local device")
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
		Routes: []snapshot.Route{
			{
				ID:           "lan",
				GatewayID:    "gateway",
				Prefix:       "192.168.50.0/24",
				Resolver:     "192.168.50.2",
				DomainSuffix: "home.arpa",
			},
		},
		ACL: []snapshot.ACLRule{
			{
				ID:             "allow-http",
				SourceDeviceID: "client",
				Destination:    "192.168.50.2/32",
				Protocol:       "tcp",
				PortFrom:       8080,
				PortTo:         8080,
			},
		},
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
