package node

import (
	"context"
	"errors"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestStartupFailureDoesNotStartTunnelWorkers(t *testing.T) {
	started := false
	want := errors.New("enrollment failed")
	app := &App{workers: []lifecycle.Worker{
		{
			Name:      "transport",
			Component: lifecycle.Func(func(context.Context) error { started = true; return nil }),
		},
	}}
	app.startup = func(context.Context) (*App, error) { return nil, want }

	if err := app.Run(context.Background()); !errors.Is(err, want) || started {
		t.Fatalf("startup failure allowed workers: started=%v error=%v", started, err)
	}
}
