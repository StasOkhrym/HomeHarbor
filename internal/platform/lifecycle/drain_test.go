package lifecycle

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestNestedEssentialFailureNotifiesProcessOnceAndPreservesError(t *testing.T) {
	var notifications atomic.Int32

	ctx := WithDrainObserver(context.Background(), func() { notifications.Add(1) })
	boom := errors.New("dependency failed")

	err := RunEssential(ctx, Worker{"outer", Func(func(ctx context.Context) error {
		return RunEssential(ctx, Worker{"inner", Func(func(context.Context) error { return boom })})
	})})

	if !errors.Is(err, boom) || notifications.Load() != 1 {
		t.Fatalf("original error=%v notifications=%d", err, notifications.Load())
	}
	if ctx.Err() != nil {
		t.Fatal("process observer changed caller cancellation ownership")
	}
}

func TestDrainObserverIgnoresOrderlyCancellationAndInvalidWiring(t *testing.T) {
	for _, mode := range []string{"cancellation", "nil-worker"} {
		t.Run(mode, func(t *testing.T) {
			var notifications atomic.Int32
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()

			ctx := WithDrainObserver(parent, func() { notifications.Add(1) })
			if mode == "nil-worker" {
				if err := RunEssential(
					ctx,
					Worker{Name: "missing"},
				); !errors.Is(
					err,
					ErrNilComponent,
				) {
					t.Fatal(err)
				}
			} else {
				if err := RunEssential(
					ctx,
					Worker{
						"owner",
						Func(
							func(ctx context.Context) error { cancel(); <-ctx.Done(); return nil },
						),
					},
				); err != nil {
					t.Fatal(err)
				}
			}

			if notifications.Load() != 0 {
				t.Fatal("orderly/invalid finite path started process drain")
			}
		})
	}
}

func TestNilObserverRetainsEmbeddedJoinContract(t *testing.T) {
	boom := errors.New("component failed")

	ctx := WithDrainObserver(context.Background(), nil)

	if err := RunEssential(
		ctx,
		Worker{"owner", Func(func(context.Context) error { return boom })},
	); !errors.Is(
		err,
		boom,
	) {
		t.Fatal(err)
	}
}

func TestNestedObserverCannotMaskParentProcessPolicy(t *testing.T) {
	var parent, child atomic.Int32

	ctx := WithDrainObserver(context.Background(), func() { parent.Add(1) })

	ctx = WithDrainObserver(ctx, func() { child.Add(1) })

	err := RunEssential(ctx, Worker{"owner", Func(func(context.Context) error { return nil })})

	if err == nil || parent.Load() != 1 || child.Load() != 1 {
		t.Fatalf(
			"nested policy masked: error=%v parent=%d child=%d",
			err,
			parent.Load(),
			child.Load(),
		)
	}
}
