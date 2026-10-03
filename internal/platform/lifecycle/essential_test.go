package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEssentialNilExitCancelsSiblings(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := make(chan struct{})
	stopped := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunEssential(ctx,
			Worker{"coordination", Func(func(context.Context) error { <-started; return nil })},
			Worker{"relay", Func(func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return nil })},
		)
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "coordination") {
			t.Fatalf("unexpected exit must name coordination: %v", err)
		}

		select {
		case <-stopped:
		default:
			t.Fatal("sibling not joined")
		}
	case <-time.After(time.Second):
		cancel()
		<-done

		t.Fatal("nil essential exit did not cancel siblings")
	}
}

func TestEssentialErrorJoinsOwners(t *testing.T) {
	boom := errors.New("transport failed")
	cleanup := errors.New("cleanup failed")
	started := make(chan struct{})
	stopped := make(chan struct{})

	err := RunEssential(
		context.Background(),
		Worker{"transport", Func(func(context.Context) error { <-started; return boom })},
		Worker{
			"owner",
			Func(
				func(ctx context.Context) error { close(started); <-ctx.Done(); close(stopped); return cleanup },
			),
		},
	)

	if !errors.Is(err, boom) || !errors.Is(err, cleanup) ||
		!strings.Contains(err.Error(), "transport") {
		t.Fatalf("worker errors lost: %v", err)
	}

	select {
	case <-stopped:
	default:
		t.Fatal("owner not joined")
	}
}

func TestParentCancelIsOrderly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunEssential(ctx, Worker{"owner", Func(func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() })})
	}()
	<-started
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("orderly cancellation: %v", err)
	}
}

func TestEssentialRejectsNilBeforeStartingOwners(t *testing.T) {
	started := false

	err := RunEssential(context.Background(),
		Worker{"valid", Func(func(context.Context) error { started = true; return nil })},
		Worker{Name: "missing"},
	)

	if started || !errors.Is(err, ErrNilComponent) || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("invalid wiring started=%v error=%v", started, err)
	}
}

func TestEssentialParentCancellationStillReportsCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	boom := errors.New("cleanup failed")

	err := RunEssential(
		ctx,
		Worker{
			"owner",
			Func(func(ctx context.Context) error { cancel(); <-ctx.Done(); return boom }),
		},
	)

	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("cleanup failure lost: %v", err)
	}
}

func TestEssentialDoesNotDiscardJoinedCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	boom := errors.New("cleanup failed")

	err := RunEssential(ctx, Worker{"owner", Func(func(ctx context.Context) error {
		cancel()
		<-ctx.Done()
		return errors.Join(ctx.Err(), boom)
	})})

	if !errors.Is(err, boom) {
		t.Fatalf("joined cleanup failure lost: %v", err)
	}
}
