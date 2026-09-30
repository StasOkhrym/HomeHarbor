package node

import (
	"context"
	"errors"
	"testing"
)

func TestRunComponentsCancelsSiblingAfterFailure(t *testing.T) {
	failure := errors.New("transport failed")
	started := make(chan struct{})
	err := RunComponents(context.Background(), func(context.Context) error {
		close(started)
		return failure
	}, func(ctx context.Context) error {
		<-started
		<-ctx.Done()
		return nil
	})
	if !errors.Is(err, failure) {
		t.Fatalf("RunComponents() error=%v", err)
	}
}
