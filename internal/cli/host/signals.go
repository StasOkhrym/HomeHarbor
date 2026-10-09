package host

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const DefaultDrainTimeout = 10 * time.Second

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
			cancel()
		}
		timer := time.NewTimer(drain)
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
