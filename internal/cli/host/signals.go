package host

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

const DefaultDrainTimeout = 10 * time.Second

type drainContextKey struct{}

type drainBudget struct {
	mu       sync.Mutex
	timeout  time.Duration
	started  bool
	deadline time.Time
}

// ConfigureDrain applies a validated role's process deadline before shutdown.
// Embedded commands without a signal host do not own a process exit boundary.
// Once cancellation begins, reconfiguration cannot extend the active deadline.
func ConfigureDrain(ctx context.Context, timeout time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if timeout <= 0 {
		return errors.New("process drain deadline must be positive")
	}

	budget, ok := ctx.Value(drainContextKey{}).(*drainBudget)
	if !ok {
		return nil
	}

	budget.mu.Lock()
	defer budget.mu.Unlock()

	if budget.started {
		return context.Canceled
	}

	budget.timeout = timeout

	return nil
}

func (b *drainBudget) begin() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.started {
		b.started = true
		b.deadline = time.Now().Add(b.timeout)
	}

	return b.deadline
}

// SignalContext cancels on the first termination signal. An unexpected
// essential exit starts the same process drain without changing caller
// cancellation ownership. A second signal or expired deadline forces exit.
func SignalContext(parent context.Context, drain time.Duration) (context.Context, func()) {
	if drain <= 0 {
		drain = DefaultDrainTimeout
	}

	input := make(chan os.Signal, 2)
	events := make(chan struct{}, 2)
	bridgeDone := make(chan struct{})
	signal.Notify(input, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for {
			select {
			case <-bridgeDone:
				return
			case <-input:
				select {
				case events <- struct{}{}:
				default:
				}
			}
		}
	}()
	ctx, stopSignals := signalContext(parent, events, drain, os.Exit)
	var once sync.Once

	return ctx, func() {
		once.Do(func() {
			signal.Stop(input)
			close(bridgeDone)
			stopSignals()
		})
	}
}

func signalContext(
	parent context.Context,
	signals <-chan struct{},
	drain time.Duration,
	hardExit func(int),
) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	budget := &drainBudget{timeout: drain}
	ctx = context.WithValue(ctx, drainContextKey{}, budget)
	failures := make(chan time.Time, 1)
	ctx = lifecycle.WithDrainObserver(ctx, func() { failures <- budget.begin() })
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		var deadline time.Time
		signaled := false
		select {
		case <-stop:
			return
		case <-parent.Done():
			cancel()
			return
		case <-signals:
			signaled = true
			deadline = budget.begin()
			cancel()
		case deadline = <-failures:
		}

		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()

		for {
			select {
			case <-stop:
				return
			case <-signals:
				if signaled {
					hardExit(130)
					return
				}

				signaled = true
				cancel()
			case <-timer.C:
				hardExit(130)
				return
			}
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}
