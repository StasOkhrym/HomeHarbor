package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/services"
	servicespg "github.com/sokhrym/go-tunnels/internal/control/services/storage"
	"github.com/sokhrym/go-tunnels/internal/testutil"
)

func TestPostgresCatalogProfileMembershipAndRollback(t *testing.T) {
	pool := testutil.Postgres(t)
	testutil.Device(t, pool, "client", "client")
	repo := servicespg.New(pool)
	ctx := context.Background()
	service := services.Service{ID: "cloud", Name: "Cloud", Kind: services.KindWeb, URL: "https://cloud.home.test", CreatedAt: time.Now().UTC()}
	if err := repo.CreateService(ctx, service); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateService(ctx, service); !errors.Is(err, services.ErrDuplicateID) {
		t.Fatalf("duplicate error=%v", err)
	}
	profile := services.AccessProfile{ID: "family", Name: "Family", DeviceIDs: []string{"client"}, ServiceIDs: []string{"cloud"}, CreatedAt: time.Now().UTC()}
	if err := repo.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}
	visible, err := repo.ListServicesForDevice(ctx, "client")
	if err != nil || len(visible) != 1 || visible[0].URL != service.URL {
		t.Fatalf("visible services=%#v %v", visible, err)
	}
	unknown, err := repo.ListServicesForDevice(ctx, "unknown")
	if err != nil || len(unknown) != 0 {
		t.Fatalf("ungranted services=%#v %v", unknown, err)
	}
	profile.ID = "invalid"
	profile.DeviceIDs = []string{"missing"}
	if err := repo.CreateProfile(ctx, profile); err == nil {
		t.Fatal("missing member accepted")
	}
	profiles, err := repo.ListProfiles(ctx)
	if err != nil || len(profiles) != 1 || profiles[0].ID != "family" || len(profiles[0].DeviceIDs) != 1 {
		t.Fatalf("partial profile survived: %#v %v", profiles, err)
	}
}
