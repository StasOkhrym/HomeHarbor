package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	profilespg "github.com/StasOkhrym/homeharbor/internal/control/profiles/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/services"
	servicespg "github.com/StasOkhrym/homeharbor/internal/control/services/storage"
	"github.com/StasOkhrym/homeharbor/internal/testutil"
)

func TestProfileMembershipRollback(t *testing.T) {
	pool := testutil.Postgres(t)

	testutil.Device(t, pool, "client", "client")
	serviceRepo := servicespg.New(pool)
	profileRepo := profilespg.New(pool)
	ctx := context.Background()
	service := services.Service{
		ID:        "cloud",
		Name:      "Cloud",
		Kind:      services.KindWeb,
		URL:       "https://cloud.home.test",
		CreatedAt: time.Now().UTC(),
	}

	if err := serviceRepo.CreateService(ctx, service); err != nil {
		t.Fatal(err)
	}

	if err := serviceRepo.CreateService(ctx, service); !errors.Is(err, services.ErrDuplicateID) {
		t.Fatalf("duplicate error=%v", err)
	}

	profile := profiles.AccessProfile{
		ID:         "family",
		Name:       "Family",
		DeviceIDs:  []string{"client"},
		ServiceIDs: []string{"cloud"},
		CreatedAt:  time.Now().UTC(),
	}

	if err := profileRepo.CreateProfile(ctx, profile); err != nil {
		t.Fatal(err)
	}

	visible, err := serviceRepo.ListServicesForDevice(ctx, "client")

	if err != nil || len(visible) != 1 || visible[0].URL != service.URL {
		t.Fatalf("visible services=%#v %v", visible, err)
	}

	unknown, err := serviceRepo.ListServicesForDevice(ctx, "unknown")

	if err != nil || len(unknown) != 0 {
		t.Fatalf("ungranted services=%#v %v", unknown, err)
	}

	profile.ID = "invalid"
	profile.DeviceIDs = []string{"missing"}

	if err := profileRepo.CreateProfile(ctx, profile); !errors.Is(
		err, profiles.ErrDeviceNotAllowed,
	) {
		t.Fatalf("missing member error=%v", err)
	}

	if _, err := pool.Exec(
		ctx,
		`UPDATE devices SET status='revoked',revoked_at=now() WHERE id='client'`,
	); err != nil {
		t.Fatal(err)
	}

	profile.ID = "inactive"
	profile.DeviceIDs = []string{"client"}

	if err := profileRepo.CreateProfile(ctx, profile); !errors.Is(
		err, profiles.ErrDeviceNotAllowed,
	) {
		t.Fatalf("inactive member error=%v", err)
	}

	profiles, err := profileRepo.ListProfiles(ctx)

	if err != nil || len(profiles) != 1 || profiles[0].ID != "family" ||
		len(profiles[0].DeviceIDs) != 1 {
		t.Fatalf("partial profile survived: %#v %v", profiles, err)
	}
}

func TestPostgresProfileRejectsDeviceRevokedDuringCreate(t *testing.T) {
	pool := testutil.Postgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	testutil.Device(t, pool, "client", "client")
	serviceRepo := servicespg.New(pool)
	if err := serviceRepo.CreateService(ctx, services.Service{
		ID: "cloud", Name: "Cloud", Kind: services.KindWeb,
		URL: "https://cloud.home.test", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	revoke, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoke.Rollback(context.Background()) }()
	if _, err = revoke.Exec(ctx,
		`UPDATE devices SET status='revoked',revoked_at=now() WHERE id='client'`); err != nil {
		t.Fatal(err)
	}
	created := make(chan error, 1)
	go func() {
		created <- profilespg.New(pool).CreateProfile(ctx, profiles.AccessProfile{
			ID: "late", Name: "Late", DeviceIDs: []string{"client"},
			ServiceIDs: []string{"cloud"}, CreatedAt: time.Now().UTC(),
		})
	}()
	if err = revoke.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-created; !errors.Is(err, profiles.ErrDeviceNotAllowed) {
		t.Fatalf("concurrent revoke error=%v", err)
	}
	items, err := profilespg.New(pool).ListProfiles(ctx)
	if err != nil || len(items) != 0 {
		t.Fatalf("rejected profile persisted: %#v, err=%v", items, err)
	}
}
