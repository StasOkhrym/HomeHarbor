package lifecycle

import (
	"context"
	"errors"
	"testing"
)

func TestRunCancelsSiblingAfterFirstFailure(t *testing.T) {
	boom := errors.New("component failed")
	started := make(chan struct{})
	stopped := make(chan struct{})

	err := Run(context.Background(),
		Func(func(context.Context) error {
			close(started)
			return boom
		}),
		Func(func(ctx context.Context) error {
			<-started
			<-ctx.Done()
			close(stopped)
			return nil
		}),
	)

	if !errors.Is(err, boom) {
		t.Fatalf("Run() error=%v, want %v", err, boom)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("Run() returned before the sibling stopped")
	}
}

func TestFuncImplementsComponent(t *testing.T) {
	var component Component = Func(func(context.Context) error { return nil })

	if err := component.Run(context.Background()); err != nil {
		t.Fatalf("component.Run() error=%v", err)
	}
}
