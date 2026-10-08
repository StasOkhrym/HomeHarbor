package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/services"
	servicespg "github.com/StasOkhrym/homeharbor/internal/control/services/storage"
	"github.com/StasOkhrym/homeharbor/internal/testutil"
)

func TestPostgresServiceCatalogContract(t *testing.T) {
	pool := testutil.Postgres(t)
	repo := servicespg.New(pool)
	ctx := context.Background()
	item := services.Service{
		ID: "cloud", Name: "Cloud", Kind: services.KindWeb,
		URL: "https://cloud.home.test", CreatedAt: time.Now().UTC(),
	}

	if err := repo.CreateService(ctx, item); err != nil {
		t.Fatal(err)
	}

	if err := repo.CreateService(ctx, item); !errors.Is(err, services.ErrDuplicateID) {
		t.Fatalf("duplicate error=%v", err)
	}

	items, err := repo.ListServices(ctx)

	if err != nil || len(items) != 1 || items[0].URL != item.URL {
		t.Fatalf("items=%#v err=%v", items, err)
	}

	visible, err := repo.ListServicesForDevice(ctx, "unknown")

	if err != nil || len(visible) != 0 {
		t.Fatalf("unexpected grant=%#v err=%v", visible, err)
	}
}
