package node

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunTicketAttemptCancelsBeforeTicketExpiry(t *testing.T) {
	var runs atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	var renewed bool
	for ctx.Err() == nil && !renewed {
		runs.Add(1)
		_, renewed = runTicketAttempt(ctx, 40*time.Millisecond, func(attemptContext context.Context) error {
			<-attemptContext.Done()
			return nil
		})
	}
	if ctx.Err() != nil {
		t.Fatalf("parent context expired before renewal: runs=%d", runs.Load())
	}
	if !renewed {
		t.Fatal("ticket attempt did not request renewal")
	}
	if runs.Load() != 1 {
		t.Fatalf("runs=%d, want one attempt before renewal", runs.Load())
	}
}

func TestRunTicketAttemptPropagatesTransportResult(t *testing.T) {
	want := context.DeadlineExceeded
	got, renewed := runTicketAttempt(context.Background(), time.Hour, func(context.Context) error { return want })
	if renewed {
		t.Fatal("transport failure was reported as ticket renewal")
	}
	if got != want {
		t.Fatalf("error=%v, want %v", got, want)
	}
}
