package storage_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/routes"
	routespg "github.com/sokhrym/go-tunnels/internal/control/routes/storage"
	"github.com/sokhrym/go-tunnels/internal/testutil"
)

func TestPostgresRouteAndDNSApprovalAreTransactional(t *testing.T) {
	pool := testutil.Postgres(t)
	testutil.Device(t, pool, "gateway", "gateway")
	repo := routespg.New(pool)
	ctx := context.Background()
	item := routes.Advertisement{
		ID:              "lan",
		GatewayDeviceID: "gateway",
		Prefix:          netip.MustParsePrefix("192.168.50.0/24"),
		Resolver:        netip.MustParseAddr("192.168.50.2"),
		DomainSuffix:    "home.test",
		Status:          routes.StatusPending,
		CreatedAt:       time.Now().UTC(),
	}
	if err := repo.Save(ctx, item); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetStatus(ctx, item.ID, routes.StatusApproved); err != nil {
		t.Fatal(err)
	}
	status := routes.StatusApproved
	items, err := repo.List(ctx, &status)
	if err != nil || len(items) != 1 || items[0].Prefix != item.Prefix || items[0].Resolver != item.Resolver {
		t.Fatalf("round trip: %#v error=%v", items, err)
	}
	var dnsStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM dns_routes WHERE id=$1`, item.ID).
		Scan(&dnsStatus); err != nil ||
		dnsStatus != string(status) {
		t.Fatalf("DNS approval diverged: %s %v", dnsStatus, err)
	}
	// A conflicting DNS suffix fails the second insert. Its LAN route must
	// also roll back, otherwise a partial advertisement survives rejection.
	item.ID = "other"
	item.Prefix = netip.MustParsePrefix("192.168.60.0/24")
	if err := repo.Save(ctx, item); err == nil {
		t.Fatal("duplicate suffix accepted")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM advertised_routes WHERE id='other'`).
		Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("partial route persisted: %d %v", count, err)
	}
	if err := repo.SetStatus(ctx, "missing", status); !errors.Is(err, routes.ErrAdvertisementNotFound) {
		t.Fatalf("missing route error = %v", err)
	}
}
