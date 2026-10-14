package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/agent/nft"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

func TestCompositeClientRemovalClearsOwnedRoutesAndWireGuard(t *testing.T) {
	gateway, _ := tunnel.NewIdentity()
	client, _ := tunnel.NewIdentity()
	value := snapshot.NetworkSnapshot{
		NetworkID: "home", Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey,
				OverlayAddress:     "100.64.0.1/32",
			},
			{
				ID:                 "client",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey,
				OverlayAddress:     "100.64.0.2/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}},
	}
	ensures := 0
	link := NewClientReconcilerWithEnsurer(
		"wg0",
		"client",
		func(context.Context, string, string, []netip.Prefix) error {
			ensures++
			return nil
		},
	)
	var deleted [][]string
	link.routes.run = func(_ context.Context, args ...string) error {
		deleted = append(deleted, append([]string(nil), args...))
		return nil
	}
	var applied wgtypes.Config

	wg, err := NewSnapshotWireGuardReconcilerWithApplier("wg0", "client", client.PrivateKey, 51820,
		func(_ string, cfg wgtypes.Config) error { applied = cfg; return nil })
	if err != nil {
		t.Fatal(err)
	}

	app := NewCompositeSnapshotApplier(nil, link, wg)
	ctx := context.Background()

	if err := app.Apply(ctx, value); err != nil {
		t.Fatal(err)
	}

	if len(applied.Peers) != 1 || len(link.routes.installed) != 1 {
		t.Fatal("fixture did not install a peer and owned route")
	}

	if err := wg.SetPeerEndpoint(
		ctx,
		gateway.PublicKey,
		netip.MustParseAddrPort("127.0.0.1:51821"),
	); err != nil {
		t.Fatal(err)
	}

	value.Revision = 2
	value.Devices = value.Devices[:1] // Other clients still use the global LAN route.

	if err := app.Apply(ctx, value); err != nil {
		t.Fatalf("client removal retained old networking: %v", err)
	}

	if !applied.ReplacePeers || len(applied.Peers) != 0 || len(wg.endpoints) != 0 ||
		len(link.routes.installed) != 0 ||
		ensures != 1 {
		t.Fatal("removed client kept peers/routes or reinstalled networking")
	}

	want := [][]string{{"route", "del", "192.168.50.0/24", "dev", "wg0"}}

	if !reflect.DeepEqual(deleted, want) {
		t.Fatalf("removed client route cleanup = %v", deleted)
	}

	if err := app.Apply(ctx, value); err != nil || len(deleted) != 1 || ensures != 1 {
		t.Fatalf("client removal was not idempotent: %v", err)
	}
}

func TestCompositeGatewayRemovalClearsFirewallAndWireGuard(t *testing.T) {
	gateway, _ := tunnel.NewIdentity()
	client, _ := tunnel.NewIdentity()

	value := gatewaySnapshotForReconciler()
	value.Devices[0].WireGuardPublicKey = gateway.PublicKey
	value.Devices[1].WireGuardPublicKey = client.PublicKey
	var live string
	g := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		nil,
		false,
		func(context.Context, string, string, []netip.Prefix) error { return nil },
	)
	g.policies = nft.NewApplierWithRunner(
		"wg0",
		nil,
		func(_ context.Context, script string) error { live = script; return nil },
	)
	g.routes.run = func(context.Context, ...string) error { return nil }
	var applied wgtypes.Config

	wg, err := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(_ string, c wgtypes.Config) error { applied = c; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	app := NewCompositeSnapshotApplier(g, wg)
	ctx := context.Background()

	if err := app.Apply(ctx, value); err != nil {
		t.Fatal(err)
	}

	if len(applied.Peers) != 1 {
		t.Fatal("fixture has no live peer")
	}

	if err := wg.SetPeerEndpoint(
		ctx,
		client.PublicKey,
		netip.MustParseAddrPort("127.0.0.1:51821"),
	); err != nil {
		t.Fatal(err)
	}

	removed := snapshot.NetworkSnapshot{NetworkID: value.NetworkID, Revision: 2}

	if err := app.Apply(ctx, removed); err != nil {
		t.Fatalf("verified removal retained old permissions: %v", err)
	}

	if g.Revision() != 2 || !applied.ReplacePeers || len(applied.Peers) != 0 ||
		len(wg.endpoints) != 0 {
		t.Fatal("removal did not clear peers and commit revision")
	}
	if strings.Contains(live, "accept comment") || !strings.Contains(live, "iifname \"wg0\" drop") {
		t.Fatalf("removal retained allows: %s", live)
	}

	if err := wg.SetPeerEndpoint(
		ctx,
		client.PublicKey,
		netip.MustParseAddrPort("127.0.0.1:51821"),
	); err == nil {
		t.Fatal("endpoint update resurrected removed gateway")
	}

	restarted, err := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(_ string, c wgtypes.Config) error { applied = c; return nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewCompositeSnapshotApplier(g, restarted).Apply(ctx, removed); err != nil {
		t.Fatalf("restart could not reapply deny state: %v", err)
	}

	if !applied.ReplacePeers || len(applied.Peers) != 0 {
		t.Fatal("restart retained old kernel peers")
	}
}

func TestSnapshotWireGuardReconcilerMergesRelayEndpointWithoutChangingPolicy(t *testing.T) {
	gateway, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	value := snapshot.NetworkSnapshot{
		Devices: []snapshot.Device{
			{
				ID:                 "client",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey,
				OverlayAddress:     "100.64.0.2/32",
			},
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey,
				OverlayAddress:     "100.64.0.1/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
	}
	var applied wgtypes.Config
	reconciler, err := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(_ string, config wgtypes.Config) error {
			applied = config
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if len(applied.Peers) != 1 || applied.Peers[0].Endpoint == nil ||
		applied.Peers[0].Endpoint.Port != 0 {
		t.Fatalf("initial peer config=%#v", applied.Peers)
	}
	allowedBefore := append([]string(nil), anyAllowedIPs(applied.Peers[0].AllowedIPs)...)
	endpoint := netip.MustParseAddrPort("127.0.0.1:51821")
	if err := reconciler.SetPeerEndpoint(
		context.Background(),
		client.PublicKey,
		endpoint,
	); err != nil {
		t.Fatal(err)
	}
	if applied.Peers[0].Endpoint == nil || applied.Peers[0].Endpoint.Port != 51821 {
		t.Fatalf("endpoint was not merged: %#v", applied.Peers[0].Endpoint)
	}
	if got := anyAllowedIPs(applied.Peers[0].AllowedIPs); len(got) != len(allowedBefore) {
		t.Fatalf("allowed prefixes changed: before=%v after=%v", allowedBefore, got)
	}
	if err := reconciler.ClearPeerEndpoint(context.Background(), client.PublicKey); err != nil {
		t.Fatal(err)
	}
	if applied.Peers[0].Endpoint == nil || applied.Peers[0].Endpoint.Port != 0 {
		t.Fatalf("endpoint was not cleared: %#v", applied.Peers[0].Endpoint)
	}
}

func TestSnapshotWireGuardReconcilerRetainsStateAfterKernelApplyFailure(t *testing.T) {
	gateway, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	client, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	value := snapshot.NetworkSnapshot{
		Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "client",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey,
				OverlayAddress:     "100.64.0.2/32",
			},
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey,
				OverlayAddress:     "100.64.0.1/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
	}
	shouldFail := false
	reconciler, err := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(_ string, _ wgtypes.Config) error {
			if shouldFail {
				return errors.New("simulated kernel failure")
			}

			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}

	endpoint := netip.MustParseAddrPort("127.0.0.1:51821")

	if err := reconciler.SetPeerEndpoint(
		context.Background(),
		client.PublicKey,
		endpoint,
	); err != nil {
		t.Fatal(err)
	}

	shouldFail = true
	value.Revision = 2

	if err := reconciler.Apply(context.Background(), value); err == nil {
		t.Fatal("failed kernel apply was accepted")
	}

	if reconciler.current == nil || reconciler.current.Revision != 1 {
		t.Fatalf("current snapshot changed after failed apply: %#v", reconciler.current)
	}

	if got := reconciler.endpoints[client.PublicKey]; got != endpoint {
		t.Fatalf("endpoint changed after failed apply: %v", got)
	}
}

func anyAllowedIPs(values []net.IPNet) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.String())
	}

	return result
}

func TestWireGuardRejectsAmbiguousIdentityBeforeMutation(t *testing.T) {
	gateway, _ := tunnel.NewIdentity()
	client, _ := tunnel.NewIdentity()
	for _, name := range []string{"subnet overlay", "duplicate public key", "duplicate overlay", "local overlay"} {
		t.Run(name, func(t *testing.T) {
			v := snapshot.NetworkSnapshot{Revision: 1, Devices: []snapshot.Device{
				{
					ID:                 "gateway",
					Role:               "gateway",
					WireGuardPublicKey: gateway.PublicKey,
					OverlayAddress:     "100.64.0.1/32",
				},
				{
					ID:                 "client",
					Role:               "client",
					WireGuardPublicKey: client.PublicKey,
					OverlayAddress:     "100.64.0.2/32",
				},
			}, Gateways: []snapshot.Gateway{{DeviceID: "gateway"}}}
			switch name {
			case "subnet overlay":
				v.Devices[1].OverlayAddress = "100.64.0.2/24"
			case "duplicate public key":
				v.Devices[1].WireGuardPublicKey = gateway.PublicKey
			case "duplicate overlay":
				v.Devices[1].OverlayAddress = v.Devices[0].OverlayAddress
			case "local overlay":
				v.Devices[0].OverlayAddress = "bad"
			}

			calls := 0
			r, err := NewSnapshotWireGuardReconcilerWithApplier(
				"wg0",
				"gateway",
				gateway.PrivateKey,
				51820,
				func(string, wgtypes.Config) error { calls++; return nil },
			)
			if err != nil {
				t.Fatal(err)
			}

			if err := r.Apply(context.Background(), v); err == nil || calls != 0 {
				t.Fatalf("malformed identity: err=%v kernel writes=%d", err, calls)
			}
		})
	}
}

func TestWireGuardRevocationReplacesPeersAndRejectsOldEndpoint(t *testing.T) {
	gateway, _ := tunnel.NewIdentity()
	client, _ := tunnel.NewIdentity()
	v := snapshot.NetworkSnapshot{Revision: 1, Devices: []snapshot.Device{
		{
			ID:                 "gateway",
			Role:               "gateway",
			WireGuardPublicKey: gateway.PublicKey,
			OverlayAddress:     "100.64.0.1/32",
		},
		{
			ID:                 "client",
			Role:               "client",
			WireGuardPublicKey: client.PublicKey,
			OverlayAddress:     "100.64.0.2/32",
		},
	}, Gateways: []snapshot.Gateway{{DeviceID: "gateway"}}}
	var config wgtypes.Config
	r, _ := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(_ string, c wgtypes.Config) error { config = c; return nil },
	)
	ctx := context.Background()

	if err := r.Apply(ctx, v); err != nil {
		t.Fatal(err)
	}

	if err := r.SetPeerEndpoint(
		ctx,
		client.PublicKey,
		netip.MustParseAddrPort("127.0.0.1:51821"),
	); err != nil {
		t.Fatal(err)
	}

	v.Revision = 2
	v.Devices = v.Devices[:1]

	if err := r.Apply(ctx, v); err != nil {
		t.Fatal(err)
	}

	if !config.ReplacePeers || len(config.Peers) != 0 {
		t.Fatal("revocation did not remove kernel peers")
	}

	if err := r.SetPeerEndpoint(
		ctx,
		client.PublicKey,
		netip.MustParseAddrPort("127.0.0.1:51821"),
	); err == nil {
		t.Fatal("transport resurrected revoked peer")
	}

	if err := r.Apply(
		ctx,
		snapshot.NetworkSnapshot{
			Revision: 1,
			Devices: append(
				v.Devices,
				snapshot.Device{
					ID:                 "client",
					Role:               "client",
					WireGuardPublicKey: client.PublicKey,
					OverlayAddress:     "100.64.0.2/32",
				},
			),
			Gateways: v.Gateways,
		},
	); err == nil {
		t.Fatal("stale snapshot resurrected revoked peer")
	}
}

func TestWireGuardRetriesSameRevisionAfterOtherOwnerFails(t *testing.T) {
	gateway, _ := tunnel.NewIdentity()
	v := snapshot.NetworkSnapshot{
		Revision: 1,
		Devices: []snapshot.Device{
			{
				ID:                 "gateway",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey,
				OverlayAddress:     "100.64.0.1/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
		ACL:      []snapshot.ACLRule{},
	}
	writes := 0
	r, _ := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gateway.PrivateKey,
		51820,
		func(string, wgtypes.Config) error { writes++; return nil },
	)
	for i := 0; i < 2; i++ {
		if err := r.Apply(context.Background(), v); err != nil {
			t.Fatalf("same revision retry %d: %v", i, err)
		}
	}

	if writes != 2 {
		t.Fatal("same revision suppressed required convergence")
	}
}
