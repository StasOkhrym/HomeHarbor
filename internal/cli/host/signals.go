package host

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const DefaultDrainTimeout = 10 * time.Second

type drainContextKey struct{}

type drainBudget struct {
	mu      sync.Mutex
	timeout time.Duration
	started bool
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

func (b *drainBudget) begin() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.started = true
	return b.timeout
}

// SignalContext cancels on the first termination signal. A second signal or
// an expired drain deadline forces a non-success process exit.
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
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-stop:
			return
		case <-parent.Done():
			cancel()
			return
		case <-signals:
		}
		deadline := budget.begin()
		cancel()
		timer := time.NewTimer(deadline)
		defer timer.Stop()
		select {
		case <-stop:
			return
		case <-signals:
			hardExit(130)
		case <-timer.C:
			hardExit(130)
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}
