// Package node assembles the long-running agent and client node processes.
// Runtime composition is shared across both entrypoints; the role selects
// ownership of forwarding policy rather than a second transport stack.
package node

import (
	"context"
	"errors"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

// App owns the cancellation tree for node transports such as coordination,
// relay forwarding, WireGuard reconciliation, and split-DNS cleanup.
type App struct {
	startup func(context.Context) (*App, error)
	workers []lifecycle.Worker
	close   func() error
}

var _ lifecycle.Component = (*App)(nil)

// Run waits until all node components stop. A component failure cancels its
// siblings and is returned after their cleanup has completed.
func (a *App) Run(ctx context.Context) (result error) {
	if a == nil {
		return lifecycle.ErrNilComponent
	}

	if a.close != nil {
		defer func() { result = errors.Join(result, a.close()) }()
	}

	if ctx.Err() != nil {
		return nil
	}
	if a.startup != nil {
		assembled, err := a.startup(ctx)
		if err != nil {
			return err
		}

		return assembled.Run(ctx)
	}

	return lifecycle.RunEssential(ctx, a.workers...)
}
