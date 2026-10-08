package profiles_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	"github.com/StasOkhrym/homeharbor/internal/control/services"
	memoryprofiles "github.com/StasOkhrym/homeharbor/internal/testutil/control/profiles"
	memoryservices "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func TestProfileRejectsInactiveDevice(t *testing.T) {
	ctx := context.Background()
	serviceStore := memoryservices.NewRepository()
	catalog := services.NewService(serviceStore, time.Now)

	if _, err := catalog.Create(ctx, services.Service{
		ID: "cloud", Name: "Cloud", Kind: services.KindWeb, URL: "https://cloud.example",
	}); err != nil {
		t.Fatal(err)
	}

	profileStore := memoryprofiles.NewRepository(serviceStore)
	owner := profiles.NewService(
		profileStore,
		catalog,
		time.Now,
		func(_ context.Context, id string) (bool, error) { return id == "active", nil },
	)

	if _, err := owner.Create(
		ctx,
		profiles.AccessProfile{
			ID:         "family",
			Name:       "Family",
			ServiceIDs: []string{"cloud"},
			DeviceIDs:  []string{"revoked"},
		},
	); !errors.Is(
		err,
		profiles.ErrDeviceNotAllowed,
	) {
		t.Fatalf("inactive membership: %v", err)
	}

	got, err := owner.List(ctx)

	if err != nil || len(got) != 0 {
		t.Fatalf("rejected profile persisted: %#v %v", got, err)
	}

	if _, err := owner.Create(
		ctx,
		profiles.AccessProfile{
			ID:         "family",
			Name:       "Family",
			ServiceIDs: []string{"cloud"},
			DeviceIDs:  []string{"active"},
		},
	); err != nil {
		t.Fatal(err)
	}

	visible, err := catalog.ListForDevice(ctx, "active")

	if err != nil || len(visible) != 1 || visible[0].ID != "cloud" {
		t.Fatalf("visible=%#v %v", visible, err)
	}
}

func TestProfileRejectsUnknownService(t *testing.T) {
	ctx := context.Background()
	serviceStore := memoryservices.NewRepository()
	owner := profiles.NewService(memoryprofiles.NewRepository(serviceStore),
		services.NewService(serviceStore, time.Now), time.Now, nil)

	if _, err := owner.Create(ctx, profiles.AccessProfile{
		ID: "family", Name: "Family", ServiceIDs: []string{"missing"},
	}); !errors.Is(err, profiles.ErrServiceNotFound) {
		t.Fatalf("unknown service error=%v", err)
	}
}

func TestProfileMembershipIsDefaultDenyAndUnionsExplicitProfiles(t *testing.T) {
	ctx := context.Background()
	serviceStore := memoryservices.NewRepository()
	catalog := services.NewService(serviceStore, time.Now)
	profileStore := memoryprofiles.NewRepository(serviceStore)
	owner := profiles.NewService(profileStore, catalog, time.Now,
		func(context.Context, string) (bool, error) { return true, nil })
	for _, item := range []services.Service{
		{ID: "cloud", Name: "Cloud", Kind: services.KindWeb, URL: "https://cloud.example"},
		{ID: "ssh", Name: "SSH", Kind: services.KindNative, URL: "https://ssh.example"},
	} {
		if _, err := catalog.Create(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	for _, profile := range []profiles.AccessProfile{
		{ID: "family", Name: "Family", DeviceIDs: []string{"phone"}, ServiceIDs: []string{"cloud"}},
		{ID: "admins", Name: "Admins", DeviceIDs: []string{"laptop"}, ServiceIDs: []string{"ssh"}},
	} {
		if _, err := owner.Create(ctx, profile); err != nil {
			t.Fatal(err)
		}
	}

	phone, err := catalog.ListForDevice(ctx, "phone")

	if err != nil || len(phone) != 1 || phone[0].ID != "cloud" {
		t.Fatalf("phone services=%#v err=%v", phone, err)
	}

	unknown, err := catalog.ListForDevice(ctx, "unknown")

	if err != nil || len(unknown) != 0 {
		t.Fatalf("unknown services=%#v err=%v", unknown, err)
	}
}

func TestProfileRepositoryReturnedSlicesAreIsolated(t *testing.T) {
	store := memoryprofiles.NewRepository(nil)
	profile := profiles.AccessProfile{
		ID: "p", DeviceIDs: []string{"device"}, ServiceIDs: []string{"service"},
	}

	if err := store.CreateProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}

	profile.DeviceIDs[0] = "changed-input"

	got, err := store.ListProfiles(context.Background())

	if err != nil || got[0].DeviceIDs[0] != "device" {
		t.Fatalf("stored input alias = %#v, err=%v", got, err)
	}

	got[0].ServiceIDs[0] = "changed-output"

	again, err := store.ListProfiles(context.Background())

	if err != nil || again[0].ServiceIDs[0] != "service" {
		t.Fatalf("returned output alias = %#v, err=%v", again, err)
	}
}
