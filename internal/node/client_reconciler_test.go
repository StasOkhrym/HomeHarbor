package node

import (
	"context"
	"net/netip"
	"reflect"
	"testing"

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
