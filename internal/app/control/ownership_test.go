package control

import (
	"context"
	"log/slog"
	"reflect"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestControlConstructionFailureClosesAcquiredResources(t *testing.T) {
	var closed []string
	stores := &runtimeStores{closers: []func(){
		func() { closed = append(closed, "redis") },
		func() { closed = append(closed, "database") },
		func() { closed = append(closed, "bus") },
	}}
	acquire := func(context.Context, config.Control, *slog.Logger) (*runtimeStores, error) { return stores, nil }
	// Invalid passkey configuration fails after stores have been acquired,
	// before any repository operation requires a real external database.
	app, err := newWithStores(context.Background(), config.Control{}, nil, acquire)
	if err == nil || app != nil {
		t.Fatal("invalid passkeys were accepted")
	}
	stores.close()
	if !reflect.DeepEqual(closed, []string{"bus", "database", "redis"}) {
		t.Fatalf("acquired resources must close once in reverse order: %v", closed)
	}
}

func TestControlShutdownWaitsForAuditBeforeClosingStores(t *testing.T) {
	var stopped bool
	stores := &runtimeStores{closers: []func(){func() {
		if !stopped {
			t.Error("stores closed before audit worker stopped")
		}
	}}}
	ctx, cancel := context.WithCancel(context.Background())
	worker := lifecycle.Func(func(ctx context.Context) error {
		cancel()
		<-ctx.Done()
		stopped = true
		return nil
	})
	if err := stores.run(ctx, worker); err != nil {
		t.Fatal(err)
	}
	if !stopped {
		t.Fatal("audit worker was not supervised")
	}
}
