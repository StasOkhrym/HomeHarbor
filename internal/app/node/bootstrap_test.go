package node

import (
	"context"
	"errors"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestFailedBootstrapDoesNotStartTunnelWorkers(t *testing.T) {
	started := false
	want := errors.New("cannot install deny guard")
	app := NewWithBootstrap(
		lifecycle.Func(func(context.Context) error { return want }),
		lifecycle.Func(func(context.Context) error { started = true; return nil }),
	)
	if err := app.Run(context.Background()); !errors.Is(err, want) || started {
		t.Fatalf("unsafe startup: started=%v error=%v", started, err)
	}
}

func TestBootstrapRunsBeforeEveryTunnelWorker(t *testing.T) {
	guarded := false
	app := NewWithBootstrap(
		lifecycle.Func(func(context.Context) error { guarded = true; return nil }),
		lifecycle.Func(func(context.Context) error {
			if !guarded {
				return errors.New("tunnel started before deny guard")
			}
			return nil
		}),
	)
	if err := app.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStartupFailureDoesNotStartTunnelWorkers(t *testing.T) {
	started := false
	want := errors.New("enrollment failed")
	app := New(lifecycle.Func(func(context.Context) error { started = true; return nil }))
	app.startup = func(context.Context) (*App, error) { return nil, want }
	if err := app.Run(context.Background()); !errors.Is(err, want) || started {
		t.Fatalf("startup failure allowed workers: started=%v error=%v", started, err)
	}
}
