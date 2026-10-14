package node

import (
	"context"
	"errors"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

func TestAppRunsWorkersThroughSharedLifecycleContract(t *testing.T) {
	boom := errors.New("node component failed")
	app := &App{workers: []lifecycle.Worker{
		{Name: "transport", Component: lifecycle.Func(func(context.Context) error { return boom })},
	}}

	if err := app.Run(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("App.Run() error=%v, want %v", err, boom)
	}
}
