package network

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestAdvertisementRequiresApproval(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(store, func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) })
	route, err := service.Advertise(context.Background(), AdvertisementRequest{ID: "route-1", GatewayDeviceID: "gateway-1", Prefix: netip.MustParsePrefix("10.20.0.0/16"), Resolver: netip.MustParseAddr("10.20.0.53"), DomainSuffix: "home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if route.Status != StatusPending {
		t.Fatalf("status=%q", route.Status)
	}
	if err = service.Approve(context.Background(), route.ID); err != nil {
		t.Fatal(err)
	}
	approved, err := service.Approved(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(approved) != 1 || approved[0].Status != StatusApproved {
		t.Fatalf("approved=%#v", approved)
	}
}

func TestAdvertisementRejectsResolverOutsidePrefix(t *testing.T) {
	service := NewService(NewMemoryStore(), time.Now)
	_, err := service.Advertise(context.Background(), AdvertisementRequest{ID: "bad", GatewayDeviceID: "gateway", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Resolver: netip.MustParseAddr("192.168.1.1"), DomainSuffix: "home.arpa"})
	if err == nil {
		t.Fatal("Advertise() error=nil")
	}
}
