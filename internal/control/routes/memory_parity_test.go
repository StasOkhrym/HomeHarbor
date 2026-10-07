package routes_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/routes"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
)

func TestListMatchesSQLOrdering(t *testing.T) {
	store := memorystore.NewRepository()
	ctx := context.Background()
	for _, item := range []domainpkg.Advertisement{
		{ID: "z", GatewayDeviceID: "gateway-z", Prefix: netip.MustParsePrefix("10.1.0.0/16"), Resolver: netip.MustParseAddr("10.1.0.1"), DomainSuffix: "z.home.arpa", Status: domainpkg.StatusPending, CreatedAt: time.Unix(1, 0)},
		{ID: "b", GatewayDeviceID: "gateway-b", Prefix: netip.MustParsePrefix("10.2.0.0/16"), Resolver: netip.MustParseAddr("10.2.0.1"), DomainSuffix: "b.home.arpa", Status: domainpkg.StatusPending, CreatedAt: time.Unix(0, 0)},
		{ID: "a", GatewayDeviceID: "gateway-a", Prefix: netip.MustParsePrefix("10.3.0.0/16"), Resolver: netip.MustParseAddr("10.3.0.1"), DomainSuffix: "a.home.arpa", Status: domainpkg.StatusPending, CreatedAt: time.Unix(0, 0)},
	} {
		if err := store.Save(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	got, err := store.List(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 3 || got[0].ID != "a" || got[1].ID != "b" || got[2].ID != "z" {
		t.Fatalf("route order = %#v", got)
	}
}

func TestSaveRejectsSQLUniqueRouteCollisionsWithoutMutation(t *testing.T) {
	first := domainpkg.Advertisement{
		ID:              "first",
		GatewayDeviceID: "gateway",
		Prefix:          netip.MustParsePrefix("10.20.0.0/16"),
		Resolver:        netip.MustParseAddr("10.20.0.1"),
		DomainSuffix:    "home.arpa",
		Status:          domainpkg.StatusApproved,
	}
	for _, test := range []struct {
		name string
		edit func(*domainpkg.Advertisement)
	}{
		{"id", func(item *domainpkg.Advertisement) { item.ID = first.ID }},
		{"gateway and prefix", func(item *domainpkg.Advertisement) { item.Prefix = first.Prefix }},
		{"gateway and suffix", func(item *domainpkg.Advertisement) { item.DomainSuffix = first.DomainSuffix }},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := memorystore.NewRepository()
			ctx := context.Background()

			if err := store.Save(ctx, first); err != nil {
				t.Fatal(err)
			}

			second := domainpkg.Advertisement{
				ID:              "second",
				GatewayDeviceID: first.GatewayDeviceID,
				Prefix:          netip.MustParsePrefix("10.30.0.0/16"),
				Resolver:        netip.MustParseAddr("10.30.0.1"),
				DomainSuffix:    "other.arpa",
				Status:          domainpkg.StatusPending,
			}

			test.edit(&second)

			if err := store.Save(ctx, second); err == nil {
				t.Fatal("route uniqueness collision accepted")
			}

			got, err := store.List(ctx, nil)

			if err != nil || len(got) != 1 || got[0] != first {
				t.Fatalf("first route changed after collision: %#v, err=%v", got, err)
			}
		})
	}
}
