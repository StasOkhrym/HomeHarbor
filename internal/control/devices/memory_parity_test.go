package devices_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
)

func TestCancelledContextReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cancel()

	_, err := memorystore.NewRepository().ListDevices(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ListDevices error = %v", err)
	}
}

func TestListDevicesMatchesSQLOrdering(t *testing.T) {
	store := memorystore.NewRepository()
	for _, device := range []devices.Device{
		{ID: "z", IdentityPublicKey: "ed-z", WireGuardPublicKey: "wg-z", CreatedAt: time.Unix(2, 0)},
		{ID: "b", IdentityPublicKey: "ed-b", WireGuardPublicKey: "wg-b", CreatedAt: time.Unix(1, 0)},
		{ID: "a", IdentityPublicKey: "ed-a", WireGuardPublicKey: "wg-a", CreatedAt: time.Unix(1, 0)},
	} {
		if err := store.SeedDevice(context.Background(), device); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].ID != "a" || got[1].ID != "b" || got[2].ID != "z" {
		t.Fatalf("device order = %#v", got)
	}
}
