package services_test

import (
	"context"
	"testing"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/services"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func TestReturnedSlicesAreIsolated(t *testing.T) {
	store := memorystore.NewRepository()
	profile := domainpkg.AccessProfile{
		ID:         "p",
		DeviceIDs:  []string{"device"},
		ServiceIDs: []string{"service"},
	}
	if err := store.CreateProfile(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	profile.DeviceIDs[0] = "changed-input"
	got, err := store.ListProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got[0].DeviceIDs[0] != "device" {
		t.Fatalf("stored input alias = %#v", got[0])
	}
	got[0].ServiceIDs[0] = "changed-output"
	again, err := store.ListProfiles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again[0].ServiceIDs[0] != "service" {
		t.Fatalf("returned output alias = %#v", again[0])
	}
}
