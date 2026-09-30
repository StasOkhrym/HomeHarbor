package node

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

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
			{ID: "client", Role: "client", WireGuardPublicKey: client.PublicKey, OverlayAddress: "100.64.0.2/32"},
			{ID: "gateway", Role: "gateway", WireGuardPublicKey: gateway.PublicKey, OverlayAddress: "100.64.0.1/32"},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
	}
	var applied wgtypes.Config
	reconciler, err := NewSnapshotWireGuardReconcilerWithApplier("wg0", "gateway", gateway.PrivateKey, 51820, func(_ string, config wgtypes.Config) error {
		applied = config
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if len(applied.Peers) != 1 || applied.Peers[0].Endpoint == nil || applied.Peers[0].Endpoint.Port != 0 {
		t.Fatalf("initial peer config=%#v", applied.Peers)
	}
	allowedBefore := append([]string(nil), anyAllowedIPs(applied.Peers[0].AllowedIPs)...)
	endpoint := netip.MustParseAddrPort("127.0.0.1:51821")
	if err := reconciler.SetPeerEndpoint(context.Background(), client.PublicKey, endpoint); err != nil {
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
			{ID: "client", Role: "client", WireGuardPublicKey: client.PublicKey, OverlayAddress: "100.64.0.2/32"},
			{ID: "gateway", Role: "gateway", WireGuardPublicKey: gateway.PublicKey, OverlayAddress: "100.64.0.1/32"},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
	}
	shouldFail := false
	reconciler, err := NewSnapshotWireGuardReconcilerWithApplier("wg0", "gateway", gateway.PrivateKey, 51820, func(_ string, _ wgtypes.Config) error {
		if shouldFail {
			return errors.New("simulated kernel failure")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	endpoint := netip.MustParseAddrPort("127.0.0.1:51821")
	if err := reconciler.SetPeerEndpoint(context.Background(), client.PublicKey, endpoint); err != nil {
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
