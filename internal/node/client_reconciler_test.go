package node

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/agent/nft"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

func TestClientReconcilerUsesLocalOverlayAndApprovedRoutes(t *testing.T) {
	var gotInterface, gotOverlay string
	var gotRoutes []netip.Prefix
	reconciler := NewClientReconcilerWithEnsurer("wg0", "client", func(_ context.Context, interfaceName, overlay string, routes []netip.Prefix) error {
		gotInterface, gotOverlay, gotRoutes = interfaceName, overlay, routes
		return nil
	})
	value := snapshot.NetworkSnapshot{
		Devices: []snapshot.Device{{ID: "gateway", Role: "gateway", OverlayAddress: "100.64.0.1/32"}, {ID: "client", Role: "client", OverlayAddress: "100.64.0.2/32"}},
		Routes:  []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}},
	}
	if err := reconciler.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if gotInterface != "wg0" || gotOverlay != "100.64.0.2/32" || !reflect.DeepEqual(gotRoutes, []netip.Prefix{netip.MustParsePrefix("192.168.50.0/24")}) {
		t.Fatalf("reconciled interface=%q overlay=%q routes=%v", gotInterface, gotOverlay, gotRoutes)
	}
}

func TestClientReconcilerRemovesRevokedRoutesAndRetriesFailedRemoval(t *testing.T) {
	var commands [][]string
	failDelete := true
	r := NewClientReconcilerWithEnsurer("wg0", "client", func(context.Context, string, string, []netip.Prefix) error { return nil })
	r.routes.run = func(_ context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		if failDelete {
			return errors.New("route busy")
		}
		return nil
	}
	v := snapshot.NetworkSnapshot{Devices: []snapshot.Device{{ID: "client", Role: "client", OverlayAddress: "100.64.0.2/32"}}, Routes: []snapshot.Route{{ID: "lan", GatewayID: "gateway", Prefix: "192.168.50.0/24"}}}
	ctx := context.Background()
	if err := r.Apply(ctx, v); err != nil {
		t.Fatal(err)
	}
	v.Routes = nil
	if err := r.Apply(ctx, v); err == nil {
		t.Fatal("route deletion failure ignored")
	}
	failDelete = false
	if err := r.Apply(ctx, v); err != nil {
		t.Fatal(err)
	}
	want := []string{"route", "del", "192.168.50.0/24", "dev", "wg0"}
	if len(commands) != 2 || !reflect.DeepEqual(commands[0], want) || !reflect.DeepEqual(commands[1], want) {
		t.Fatalf("revocation retries=%v", commands)
	}
}

func TestGatewayRoutesExcludeLocallyServedLAN(t *testing.T) {
	var routes []netip.Prefix
	r := NewGatewayReconcilerWithEnsurer("wg0", "gateway", nil, false, func(_ context.Context, _, _ string, p []netip.Prefix) error { routes = p; return nil })
	r.policies = nft.NewApplierWithRunner("wg0", nil, func(context.Context, string) error { return nil })
	if err := r.Apply(context.Background(), gatewaySnapshotForReconciler()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(routes, []netip.Prefix{netip.MustParsePrefix("10.200.0.2/32")}) {
		t.Fatalf("gateway must route peers, never its LAN into itself: %v", routes)
	}
}

func TestClientReconcilerRejectsDefaultRouteBeforeEnsure(t *testing.T) {
	called := false
	reconciler := NewClientReconcilerWithEnsurer("wg0", "client", func(context.Context, string, string, []netip.Prefix) error {
		called = true
		return nil
	})
	err := reconciler.Apply(context.Background(), snapshot.NetworkSnapshot{
		Devices: []snapshot.Device{{ID: "client", Role: "client", OverlayAddress: "100.64.0.2/32"}},
		Routes:  []snapshot.Route{{ID: "default", GatewayID: "gateway", Prefix: "0.0.0.0/0"}},
	})
	if err == nil || called {
		t.Fatalf("default route err=%v ensure called=%v", err, called)
	}
}
