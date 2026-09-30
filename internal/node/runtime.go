package node

import (
	"context"
	"sync"
)

// RunComponents runs independent node components under one cancellation tree.
// The first component failure stops the remaining transports and returns the
// original error; this keeps a dead coordination stream from leaving a live
// relay bridge behind with stale policy.
func RunComponents(ctx context.Context, components ...func(context.Context) error) error {
	if len(components) == 0 {
		return nil
	}
	componentContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, len(components))
	var waitGroup sync.WaitGroup
	waitGroup.Add(len(components))
	for _, component := range components {
		go func(run func(context.Context) error) {
			defer waitGroup.Done()
			results <- run(componentContext)
		}(component)
	}
	var first error
	for range components {
		err := <-results
		if err != nil && first == nil {
			first = err
			cancel()
		}
	}
	waitGroup.Wait()
	return first
}
