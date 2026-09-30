package node

import (
	"context"

	"github.com/sokhrym/go-tunnels/internal/platform/lifecycle"
)

// RunComponents runs independent node components under one cancellation tree.
// The first component failure stops the remaining transports and returns the
// original error; this keeps a dead coordination stream from leaving a live
// relay bridge behind with stale policy.
func RunComponents(ctx context.Context, components ...func(context.Context) error) error {
	runners := make([]lifecycle.Component, len(components))
	for index, component := range components {
		if component == nil {
			return lifecycle.ErrNilComponent
		}
		runners[index] = lifecycle.Func(component)
	}
	return lifecycle.Run(ctx, runners...)
}
