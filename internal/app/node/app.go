// Package node assembles the long-running agent and client node processes.
// Runtime composition and flags are shared across both entrypoints; the role
// selects ownership of forwarding policy rather than a second transport stack.
package node

import (
	"context"

	"github.com/StasOkhrym/homeharbor/internal/platform/lifecycle"
)

// App owns the cancellation tree for node transports such as coordination,
// relay forwarding, WireGuard reconciliation, and split-DNS cleanup.
type App struct {
	startup    func(context.Context) (*App, error)
	bootstrap  lifecycle.Component
	components []lifecycle.Component
}

var _ lifecycle.Component = (*App)(nil)

// New copies the component list so later caller mutations cannot change the
// running application. NewRuntime defers concrete startup to Run.
func New(components ...lifecycle.Component) *App {
	owned := append([]lifecycle.Component(nil), components...)
	return &App{components: owned}
}

// NewWithBootstrap assembles a preflight boundary that must finish before any
// concurrent worker opens a tunnel. A failed gateway guard prevents startup.
func NewWithBootstrap(bootstrap lifecycle.Component, components ...lifecycle.Component) *App {
	app := New(components...)
	app.bootstrap = bootstrap
	return app
}

// Run waits until all node components stop. A component failure cancels its
// siblings and is returned after their cleanup has completed.
func (a *App) Run(ctx context.Context) error {
	if a == nil {
		return lifecycle.ErrNilComponent
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
	if a.bootstrap != nil {
		if err := a.bootstrap.Run(ctx); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return lifecycle.Run(ctx, a.components...)
}
