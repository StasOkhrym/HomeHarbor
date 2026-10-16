package node

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/agent/nft"
)

func TestGracefulCleanupRetiresOnlyOwnedPeersAndRoutes(t *testing.T) {
	value, gatewayKey, _ := telemetryTopology(t)
	var updates []wgtypes.Config

	peerOwner, err := NewSnapshotWireGuardReconcilerWithApplier(
		"wg0",
		"gateway",
		gatewayKey.PrivateKey,
		51820,
		func(_ string, c wgtypes.Config) error { updates = append(updates, c); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := peerOwner.Close(t.Context()); err != nil || len(updates) != 0 {
		t.Fatal("unused owner touched kernel")
	}

	if err := peerOwner.Apply(t.Context(), value); err != nil {
		t.Fatal(err)
	}

	if err := peerOwner.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	last := updates[len(updates)-1]

	if !last.ReplacePeers || len(last.Peers) != 0 || last.PrivateKey != nil ||
		last.ListenPort != nil {
		t.Fatal("cleanup did not retire only owned peers")
	}

	if err := peerOwner.Close(t.Context()); err != nil || len(updates) != 2 {
		t.Fatal("peer cleanup was not idempotent")
	}

	client := NewClientReconcilerWithEnsurer(
		"wg0",
		"client",
		func(context.Context, string, string, []netip.Prefix) error { return nil },
	)
	var commands [][]string
	client.routes.run = func(_ context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	}

	if err := client.Apply(t.Context(), value); err != nil {
		t.Fatal(err)
	}

	if err := client.Close(t.Context()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"route", "del", "10.10.0.0/24", "dev", "wg0"}}

	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("cleanup changed unrelated routes: %v", commands)
	}

	if err := client.Close(t.Context()); err != nil || len(commands) != 1 {
		t.Fatal("route cleanup not idempotent")
	}
}

func TestGatewayCleanupKeepsDenyOnRouteRemovalFailure(t *testing.T) {
	g := NewGatewayReconcilerWithEnsurer(
		"wg0",
		"gateway",
		nil,
		false,
		func(context.Context, string, string, []netip.Prefix) error { return nil },
	)
	denied := false
	g.policies = nft.NewApplierWithRunner(
		"wg0",
		nil,
		func(context.Context, string) error { denied = true; return nil },
	)

	prefix := netip.MustParsePrefix("10.10.0.0/24")
	g.routes.installed[prefix] = struct{}{}
	failure := errors.New("route cleanup failed")
	g.routes.run = func(context.Context, ...string) error {
		if !denied {
			t.Fatal("route mutation before deny")
		}

		return failure
	}

	if err := g.Close(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("cleanup failure lost: %v", err)
	}

	if !denied || len(g.routes.installed) != 1 {
		t.Fatal("failed cleanup released deny or lost ownership")
	}
}
