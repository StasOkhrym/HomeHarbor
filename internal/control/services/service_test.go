package services

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceRequiresHTTPSAndSupportsProfiles(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(store, func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) })
	if _, err := service.Create(context.Background(), Service{ID: "cloud", Name: "Nextcloud", Kind: KindWeb, URL: "http://cloud.home"}); err == nil {
		t.Fatal("insecure service URL accepted")
	}
	created, err := service.Create(context.Background(), Service{ID: "cloud", Name: "Nextcloud", Kind: KindWeb, URL: "https://cloud.home.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if created.CreatedAt.IsZero() {
		t.Fatal("created timestamp is empty")
	}
	profile, err := service.CreateProfile(context.Background(), AccessProfile{ID: "family", Name: "Family", ServiceIDs: []string{"cloud"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.ServiceIDs) != 1 || profile.ServiceIDs[0] != "cloud" {
		t.Fatalf("profile=%#v", profile)
	}
}

func TestServiceRejectsDuplicateIDs(t *testing.T) {
	service := NewService(NewMemoryStore(), time.Now)
	item := Service{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://cloud.example.com"}
	if _, err := service.Create(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(context.Background(), item); err == nil {
		t.Fatal("duplicate service accepted")
	}
}

func TestProfileRejectsUnknownService(t *testing.T) {
	service := NewService(NewMemoryStore(), time.Now)
	if _, err := service.CreateProfile(context.Background(), AccessProfile{ID: "family", Name: "Family", ServiceIDs: []string{"missing"}}); err == nil {
		t.Fatal("profile referenced unknown service")
	}
}

func TestServiceRejectsUnsafeOptionalURLs(t *testing.T) {
	cases := []Service{
		{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://user:password@cloud.example"},
		{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://cloud.example", NativeURL: "javascript:alert(1)"},
		{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://cloud.example", HealthURL: "http://cloud.example/health"},
		{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://cloud.example#fragment"},
	}
	for index, item := range cases {
		if _, err := NewService(NewMemoryStore(), time.Now).Create(context.Background(), item); err == nil {
			t.Errorf("case %d: unsafe service URL accepted", index)
		}
	}
}

func TestServiceAllowsExplicitNativeDeepLink(t *testing.T) {
	item, err := NewService(NewMemoryStore(), time.Now).Create(context.Background(), Service{
		ID: "cloud", Name: "Cloud", Kind: KindNative, URL: "https://cloud.example", NativeURL: "nextcloud://cloud.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	if item.NativeURL != "nextcloud://cloud.example" {
		t.Fatalf("native URL=%q", item.NativeURL)
	}
}

func TestProfileRequiresActiveDevicesWhenDeviceValidationIsConfigured(t *testing.T) {
	service := NewService(NewMemoryStore(), time.Now, WithDeviceActiveChecker(func(_ context.Context, id string) (bool, error) {
		return id == "active-phone", nil
	}))
	if _, err := service.Create(context.Background(), Service{ID: "cloud", Name: "Cloud", Kind: KindWeb, URL: "https://cloud.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateProfile(context.Background(), AccessProfile{ID: "family", Name: "Family", ServiceIDs: []string{"cloud"}, DeviceIDs: []string{"revoked-phone"}}); !errors.Is(err, ErrDeviceNotAllowed) {
		t.Fatalf("revoked device error=%v", err)
	}
	profile, err := service.CreateProfile(context.Background(), AccessProfile{ID: "family", Name: "Family", ServiceIDs: []string{"cloud"}, DeviceIDs: []string{"active-phone"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.DeviceIDs) != 1 || profile.DeviceIDs[0] != "active-phone" {
		t.Fatalf("profile=%#v", profile)
	}
}
