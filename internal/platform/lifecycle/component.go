// Package lifecycle contains the deliberately small contracts shared by
// executable runtimes. It is not a service locator: each application still
// owns its dependencies and shutdown order explicitly.
package lifecycle

import (
	"context"
	"errors"
	"sync"
)

// Component is the common contract for a long-running executable component.
// Run must return when ctx is cancelled or when the component cannot continue.
type Component interface {
	Run(context.Context) error
}

// Func adapts a function to Component. It keeps executable wiring concise
// while preserving one contract for HTTP servers, node transports, and future
// background workers.
type Func func(context.Context) error

// Run executes components under one cancellation tree. The first component
// failure cancels its siblings, then the runner waits for every goroutine so a
// caller never returns while a component still owns a socket or goroutine.
func Run(ctx context.Context, components ...Component) error {
	for _, component := range components {
		if component == nil {
			return ErrNilComponent
		}
	}
	if len(components) == 0 {
		return nil
	}

	componentContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(components))
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(components))
	for _, component := range components {
		go func(component Component) {
			defer waitGroup.Done()
			results <- component.Run(componentContext)
		}(component)
	}

	var first error
	for range components {
		if err := <-results; err != nil && first == nil {
			first = err
			cancel()
		}
	}
	waitGroup.Wait()
	return first
}

// Run executes the function as a lifecycle component.
func (f Func) Run(ctx context.Context) error {
	if f == nil {
		return ErrNilComponent
	}

	return f(ctx)
}

// ErrNilComponent identifies invalid runtime wiring before any goroutine is
// started. Returning it early avoids a less useful nil-function panic.
var ErrNilComponent = errors.New("nil lifecycle component")
