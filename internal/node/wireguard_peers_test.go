package node

import (
	"errors"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
)

func TestBuildWireGuardPeerConfigsScopesGatewayRoutes(t *testing.T) {
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
		Routes:   []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "10.10.0.0/24"}},
	}
	peers, err := BuildWireGuardPeerConfigs(value, "client")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || len(peers[0].AllowedPrefixes) != 2 {
		t.Fatalf("client peers=%#v", peers)
	}
	if peers[0].AllowedPrefixes[0].String() != "10.10.0.0/24" || peers[0].AllowedPrefixes[1].String() != "100.64.0.1/32" {
		t.Fatalf("client allowed prefixes=%v", peers[0].AllowedPrefixes)
	}

	peers, err = BuildWireGuardPeerConfigs(value, "gateway")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || len(peers[0].AllowedPrefixes) != 1 || peers[0].AllowedPrefixes[0].String() != "100.64.0.2/32" {
		t.Fatalf("gateway peers=%#v", peers)
	}
}

func TestBuildWireGuardPeerConfigsRejectsUnsafeOrIncompleteTopology(t *testing.T) {
	gateway, err := tunnel.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	value := snapshot.NetworkSnapshot{
		Devices:  []snapshot.Device{{ID: "gateway", Role: "gateway", WireGuardPublicKey: gateway.PublicKey, OverlayAddress: "100.64.0.1/32"}},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway"}},
		Routes:   []snapshot.Route{{ID: "default", GatewayID: "gateway", Prefix: "0.0.0.0/0"}},
	}
	if _, err := BuildWireGuardPeerConfigs(value, "gateway"); err == nil {
		// A gateway does not need a peer for its own route, but the route itself
		// must still be rejected before any future applier can consume it.
		t.Fatal("default route was accepted")
	}
	if _, err := BuildWireGuardPeerConfigs(snapshot.NetworkSnapshot{}, "missing"); !errors.Is(err, ErrLocalDeviceMissing) {
		t.Fatalf("missing local device error=%v", err)
	}
}
