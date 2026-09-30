// Package node assembles the long-running agent and client node processes.
// Role-specific configuration remains in the entrypoints; this app owns only
// the shared component lifecycle and therefore stays small enough to extract
// when the node runtimes become separate services.
package node

import (
	"context"

	"github.com/sokhrym/go-tunnels/internal/platform/lifecycle"
)

// App owns the cancellation tree for node transports such as coordination,
// relay forwarding, WireGuard reconciliation, and split-DNS cleanup.
type App struct {
	components []lifecycle.Component
}

var _ lifecycle.Component = (*App)(nil)

// New copies the component list so later caller mutations cannot change the
// running application. Dependency construction remains outside this package.
func New(components ...lifecycle.Component) *App {
	owned := append([]lifecycle.Component(nil), components...)
	return &App{components: owned}
}

// Run waits until all node components stop. A component failure cancels its
// siblings and is returned after their cleanup has completed.
func (a *App) Run(ctx context.Context) error {
	if a == nil {
		return lifecycle.ErrNilComponent
	}
	return lifecycle.Run(ctx, a.components...)
}
