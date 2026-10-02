package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type blockingAuditSink struct {
	entered chan audit.Event
	result  chan error
}

func (s blockingAuditSink) Write(ctx context.Context, event audit.Event) error {
	select {
	case s.entered <- event:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-s.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestAuditPipelineAcknowledgesOnlyDurableWrites(t *testing.T) {
	bus := gochannel.NewGoChannel(gochannel.Config{PreserveContext: true}, nil)
	t.Cleanup(func() { _ = bus.Close() })
	sink := blockingAuditSink{entered: make(chan audit.Event), result: make(chan error)}
	pipeline := NewAuditPipeline(bus, sink)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	defer func() { cancel(); <-done }()
	select {
	case <-pipeline.Ready():
	case <-ctx.Done():
		t.Fatal("consumer never subscribed")
	}
	msg := message.NewMessage(
		"outbox:42",
		[]byte(
			`{"type":"device.enrolled","aggregate_id":"device-1","occurred_at":"2026-09-30T12:00:00Z"}`,
		),
	)
	published := make(chan error, 1)
	go func() { published <- pipeline.Publish(ctx, "device.enrolled", msg) }()
	var event audit.Event
	select {
	case event = <-sink.entered:
	case <-ctx.Done():
		t.Fatal("audit write was not attempted")
	}
	if event.ID != "outbox:42" || event.TargetID != "device-1" {
		t.Fatalf("audit lost delivery identity: %#v", event)
	}
	select {
	case err := <-published:
		t.Fatalf("publish completed before commit: %v", err)
	default:
	}
	want := errors.New("database unavailable")
	sink.result <- want
	if err := <-published; !errors.Is(err, want) {
		t.Fatalf("publish error = %v, want durable write failure", err)
	}
	// A retry uses the same delivery ID. The SQL sink deduplicates it if the
	// previous commit succeeded but its acknowledgement was lost.
	go func() { published <- pipeline.Publish(ctx, "device.enrolled", msg) }()
	select {
	case <-sink.entered:
	case <-ctx.Done():
		t.Fatal("retry did not reach durable sink")
	}
	sink.result <- nil
	if err := <-published; err != nil {
		t.Fatal(err)
	}
}

func TestAuditPipelineDoesNotLoseEventsBeforeSubscription(t *testing.T) {
	bus := gochannel.NewGoChannel(gochannel.Config{PreserveContext: true}, nil)
	defer func() { _ = bus.Close() }()
	pipeline := NewAuditPipeline(bus, &recordingAuditSink{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := pipeline.Publish(
		ctx,
		"device.enrolled",
		message.NewMessage("pending", nil),
	); !errors.Is(
		err,
		context.Canceled,
	) {
		t.Fatalf("unstarted consumer discarded event: %v", err)
	}
}
