package networkplan

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

func signedPlanFixture(
	t *testing.T,
) (snapshot.NetworkSnapshot, ed25519.PublicKey, ed25519.PrivateKey, Bounds) {
	t.Helper()

	root, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	client, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	gateway, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	value := snapshot.NetworkSnapshot{
		NetworkID: "sandbox-network",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "client-1",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey().String(),
				OverlayAddress:     "10.200.0.3/32",
			},
			{
				ID:                 "gateway-1",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey().String(),
				OverlayAddress:     "10.200.0.2/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway-1"}},
		Routes: []snapshot.Route{
			{
				ID:           "private",
				GatewayID:    "gateway-1",
				Prefix:       "172.29.50.0/24",
				DomainSuffix: "sandbox.home.arpa",
				Resolver:     "172.29.50.53",
			},
		},
	}

	return value, root, private, Bounds{
		Overlay: netip.MustParsePrefix("10.200.0.0/24"),
		Private: netip.MustParsePrefix("172.29.50.0/24"),
		Suffix:  "sandbox.home.arpa",
	}
}

func TestPlanRejectsDefaultRouteAndForeignSuffix(t *testing.T) {
	value, root, key, bounds := signedPlanFixture(t)

	valid, err := snapshot.Sign(value, key, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	plan, err := CompileSigned(valid, root, "sandbox-network", "client-1", bounds)

	if err != nil || plan.Revision != 1 || len(plan.Peers) != 1 || len(plan.Routes) != 1 ||
		len(plan.DNS) != 1 || plan.DNS[0].Suffix != bounds.Suffix {
		t.Fatalf("valid bounded signed plan rejected: plan=%+v err=%v", plan, err)
	}

	value.Routes[0].DomainSuffix = "foreign.example"

	foreign, err := snapshot.Sign(value, key, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CompileSigned(foreign, root, "sandbox-network", "client-1", bounds); err == nil {
		t.Fatal("signed foreign DNS suffix accepted")
	}

	value.Routes[0].DomainSuffix = bounds.Suffix
	value.Routes[0].Prefix = "0.0.0.0/0"

	if _, err := snapshot.Sign(value, key, "root-1"); err == nil {
		t.Fatal("default route entered a signed snapshot")
	}

	value.Routes[0].Prefix = "172.29.0.0/16"
	value.Routes[0].Resolver = "172.29.50.53"

	tooBroad, err := snapshot.Sign(value, key, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CompileSigned(tooBroad, root, "sandbox-network", "client-1", bounds); err == nil {
		t.Fatal("signed route outside private bounds accepted")
	}
}

func TestSignedRemovalProducesClosedPlan(t *testing.T) {
	value, root, key, bounds := signedPlanFixture(t)
	value.Revision = 2
	value.Devices = value.Devices[1:]

	envelope, err := snapshot.Sign(value, key, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	plan, err := CompileSigned(envelope, root, "sandbox-network", "client-1", bounds)

	if err != nil || !plan.Revoked || len(plan.Peers) != 0 || len(plan.Routes) != 0 ||
		len(plan.DNS) != 0 {
		t.Fatalf("signed device removal retained native access: plan=%+v err=%v", plan, err)
	}
}
