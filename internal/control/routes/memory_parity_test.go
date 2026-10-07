package routes_test

import (
	"context"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/routes"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/routes"
)

func TestListMatchesSQLOrdering(t *testing.T) {
	store := memorystore.NewRepository()
	ctx := context.Background()
	for _, item := range []domainpkg.Advertisement{
		{ID: "z", CreatedAt: time.Unix(1, 0)},
		{ID: "b", CreatedAt: time.Unix(0, 0)},
		{ID: "a", CreatedAt: time.Unix(0, 0)},
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
