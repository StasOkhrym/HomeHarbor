package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Worker names a long-running owner whose unexpected exit stops the runtime.
// Finite bootstrap operations belong outside RunEssential.
type Worker struct {
	Name      string
	Component Component
}

// RunEssential cancels siblings on any unexpected exit and joins all owners.
// Cancellation errors during shutdown are orderly; other errors retain their
// original identity and owner name, including failures during cleanup.
func RunEssential(ctx context.Context, workers ...Worker) error {
	for _, worker := range workers {
		if worker.Component == nil {
			return fmt.Errorf("worker %q: %w", worker.Name, ErrNilComponent)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		name       string
		err        error
		unexpected bool
	}
	results := make(chan result, len(workers))
	var owners sync.WaitGroup
	owners.Add(len(workers))
	for _, worker := range workers {
		go func(worker Worker) {
			defer owners.Done()
			err := worker.Component.Run(owned)
			results <- result{worker.Name, err, owned.Err() == nil}
		}(worker)
	}
	var errs []error
	for range workers {
		result := <-results
		if result.unexpected {
			cancel()
		}
		if result.err == nil {
			if result.unexpected {
				errs = append(
					errs,
					fmt.Errorf("essential worker %q exited unexpectedly", result.name),
				)
			}
			continue
		}
		if !result.unexpected && cancellationOnly(result.err) {
			continue
		}
		errs = append(errs, fmt.Errorf("essential worker %q: %w", result.name, result.err))
	}
	owners.Wait()
	return errors.Join(errs...)
}

// A joined cancellation must not hide a substantive cleanup error.
func cancellationOnly(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}

		for _, child := range children {
			if !cancellationOnly(child) {
				return false
			}
		}

		return true
	}

	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return cancellationOnly(wrapped.Unwrap())
	}

	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
