package routes_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/routes"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
)

func TestAdvertisementRequiresApproval(t *testing.T) {
	store := memorystore.NewRepository()
	service := domainpkg.NewService(
		store,
		func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) },
	)

	route, err := service.Advertise(
		context.Background(),
		domainpkg.AdvertisementRequest{
			ID:              "route-1",
			GatewayDeviceID: "gateway-1",
			Prefix:          netip.MustParsePrefix("10.20.0.0/16"),
			Resolver:        netip.MustParseAddr("10.20.0.53"),
			DomainSuffix:    "home.arpa",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if route.Status != domainpkg.StatusPending {
		t.Fatalf("status=%q", route.Status)
	}

	if err = service.Approve(context.Background(), route.ID); err != nil {
		t.Fatal(err)
	}

	approved, err := service.Approved(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(approved) != 1 || approved[0].Status != domainpkg.StatusApproved {
		t.Fatalf("approved=%#v", approved)
	}
}

func TestAdvertisementRejectsResolverOutsidePrefix(t *testing.T) {
	service := domainpkg.NewService(memorystore.NewRepository(), time.Now)

	_, err := service.Advertise(
		context.Background(),
		domainpkg.AdvertisementRequest{
			ID:              "bad",
			GatewayDeviceID: "gateway",
			Prefix:          netip.MustParsePrefix("10.0.0.0/24"),
			Resolver:        netip.MustParseAddr("192.168.1.1"),
			DomainSuffix:    "home.arpa",
		},
	)

	if err == nil {
		t.Fatal("Advertise() error=nil")
	}
}

func TestAdvertisementRejectsDefaultRoute(t *testing.T) {
	service := domainpkg.NewService(memorystore.NewRepository(), time.Now)

	_, err := service.Advertise(context.Background(), domainpkg.AdvertisementRequest{
		ID: "internet", GatewayDeviceID: "gateway", Prefix: netip.MustParsePrefix("0.0.0.0/0"),
		Resolver: netip.MustParseAddr("10.0.0.53"), DomainSuffix: "home.arpa",
	})

	if err == nil {
		t.Fatal("Advertise() accepted a default route")
	}
}

func TestAdvertisementRejectsUnsafeDomainSuffix(t *testing.T) {
	service := domainpkg.NewService(memorystore.NewRepository(), time.Now)
	for _, suffix := range []string{".home.arpa", "home..arpa", "home.arpa;revert", "-home.arpa", "home-.arpa"} {
		_, err := service.Advertise(context.Background(), domainpkg.AdvertisementRequest{
			ID: suffix, GatewayDeviceID: "gateway", Prefix: netip.MustParsePrefix("10.20.0.0/16"),
			Resolver: netip.MustParseAddr("10.20.0.53"), DomainSuffix: suffix,
		})

		if err == nil {
			t.Fatalf("Advertise() accepted unsafe suffix %q", suffix)
		}
	}
}
