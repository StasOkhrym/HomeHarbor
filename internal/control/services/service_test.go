package services_test

import (
	"context"
	"testing"
	"time"

	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/services"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/services"
)

func TestServiceRequiresHTTPS(t *testing.T) {
	store := memorystore.NewRepository()
	service := domainpkg.NewService(
		store,
		func() time.Time { return time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC) },
	)

	if _, err := service.Create(
		context.Background(),
		domainpkg.Service{
			ID:   "cloud",
			Name: "Nextcloud",
			Kind: domainpkg.KindWeb,
			URL:  "http://cloud.home",
		},
	); err == nil {
		t.Fatal("insecure service URL accepted")
	}

	created, err := service.Create(
		context.Background(),
		domainpkg.Service{
			ID:   "cloud",
			Name: "Nextcloud",
			Kind: domainpkg.KindWeb,
			URL:  "https://cloud.home.example.com",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if created.CreatedAt.IsZero() {
		t.Fatal("created timestamp is empty")
	}
}

func TestServiceRejectsDuplicateIDs(t *testing.T) {
	service := domainpkg.NewService(memorystore.NewRepository(), time.Now)
	item := domainpkg.Service{
		ID:   "cloud",
		Name: "Cloud",
		Kind: domainpkg.KindWeb,
		URL:  "https://cloud.example.com",
	}

	if _, err := service.Create(context.Background(), item); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Create(context.Background(), item); err == nil {
		t.Fatal("duplicate service accepted")
	}
}

func TestServiceRejectsUnsafeOptionalURLs(t *testing.T) {
	cases := []domainpkg.Service{
		{
			ID:   "cloud",
			Name: "Cloud",
			Kind: domainpkg.KindWeb,
			URL:  "https://user:password@cloud.example",
		},
		{
			ID:        "cloud",
			Name:      "Cloud",
			Kind:      domainpkg.KindWeb,
			URL:       "https://cloud.example",
			NativeURL: "javascript:alert(1)",
		},
		{
			ID:        "cloud",
			Name:      "Cloud",
			Kind:      domainpkg.KindWeb,
			URL:       "https://cloud.example",
			HealthURL: "http://cloud.example/health",
		},
		{
			ID:   "cloud",
			Name: "Cloud",
			Kind: domainpkg.KindWeb,
			URL:  "https://cloud.example#fragment",
		},
	}
	for index, item := range cases {
		if _, err := domainpkg.NewService(
			memorystore.NewRepository(),
			time.Now,
		).Create(context.Background(), item); err == nil {
			t.Errorf("case %d: unsafe service URL accepted", index)
		}
	}
}

func TestServiceAllowsExplicitNativeDeepLink(t *testing.T) {
	item, err := domainpkg.NewService(memorystore.NewRepository(), time.Now).
		Create(context.Background(), domainpkg.Service{
			ID:        "cloud",
			Name:      "Cloud",
			Kind:      domainpkg.KindNative,
			URL:       "https://cloud.example",
			NativeURL: "nextcloud://cloud.example",
		})
	if err != nil {
		t.Fatal(err)
	}

	if item.NativeURL != "nextcloud://cloud.example" {
		t.Fatalf("native URL=%q", item.NativeURL)
	}
}
