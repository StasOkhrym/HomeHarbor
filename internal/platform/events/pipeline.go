package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/ThreeDotsLabs/watermill/message"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

const auditTopic = "internal.audit.outbox"

type auditDeliveryKey struct{}

type auditDelivery struct {
	result chan error
	ctx    context.Context
}

// AuditPipeline gates outbox acknowledgement on the durable sink. The bus must
// preserve message contexts; a missing delivery receipt fails closed instead of
// mistaking GoChannel's asynchronous Publish return for a database commit.
type AuditPipeline struct {
	bus interface {
		message.Publisher
		message.Subscriber
	}
	sink    AuditSink
	ready   chan struct{}
	done    chan struct{}
	running atomic.Bool
}

// NewAuditPipeline assembles dependencies without starting subscriptions or workers.
func NewAuditPipeline(bus interface {
	message.Publisher
	message.Subscriber
}, sink AuditSink,
) *AuditPipeline {
	return &AuditPipeline{
		bus:   bus,
		sink:  sink,
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
}

// Ready closes after subscription registration, before any outbox dispatch.
func (p *AuditPipeline) Ready() <-chan struct{} { return p.ready }

// Check reports whether the consumer is serving durable delivery receipts.
func (p *AuditPipeline) Check() error {
	if !p.running.Load() {
		return errors.New("audit consumer unavailable")
	}
	return nil
}

// Run owns the subscription and finishes all writes before returning. A write
// failure is returned to its publisher; the durable outbox remains retryable.
func (p *AuditPipeline) Run(ctx context.Context) error {
	defer close(p.done)
	if p.bus == nil || p.sink == nil {
		return errors.New("audit pipeline dependencies are required")
	}
	messages, err := p.bus.Subscribe(ctx, auditTopic)
	if err != nil {
		return err
	}
	p.running.Store(true)
	defer p.running.Store(false)
	close(p.ready)
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-messages:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("audit subscription closed unexpectedly")
			}
			delivery, ok := msg.Context().Value(auditDeliveryKey{}).(*auditDelivery)
			if !ok {
				msg.Ack()
				return errors.New("audit bus must preserve delivery context")
			}
			var event devices.Event
			err := json.Unmarshal(msg.Payload, &event)
			if err == nil &&
				(event.Type == "" || event.AggregateID == "" || event.OccurredAt.IsZero()) {
				err = errors.New("invalid outbox audit event")
			}
			if err == nil {
				writeCtx, cancel := context.WithCancel(delivery.ctx)
				stop := context.AfterFunc(ctx, cancel)
				err = p.sink.Write(
					writeCtx,
					audit.Event{
						ID:         msg.UUID,
						OccurredAt: event.OccurredAt,
						ActorType:  "device",
						ActorID:    event.AggregateID,
						Action:     event.Type,
						TargetType: "device",
						TargetID:   event.AggregateID,
						Metadata:   map[string]any{},
					},
				)
				stop()
				cancel()
			}
			// SQL is the retry queue. Ack even a failed bus attempt to avoid a
			// second unowned GoChannel retry racing the next outbox delivery.
			msg.Ack()
			delivery.result <- err
		}
	}
}

// Publish waits for the durable write, then emits the weakly coupled domain
// notification. Cancellation never acknowledges an uncommitted outbox row.
func (p *AuditPipeline) Publish(ctx context.Context, topic string, msg *message.Message) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return errors.New("audit pipeline stopped")
	case <-p.ready:
	}
	if err := p.Check(); err != nil {
		return err
	}
	delivery := &auditDelivery{result: make(chan error, 1), ctx: ctx}
	attempt := msg.Copy()
	attempt.SetContext(context.WithValue(ctx, auditDeliveryKey{}, delivery))
	if err := p.bus.Publish(auditTopic, attempt); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return errors.New("audit pipeline stopped before acknowledgement")
	case err := <-delivery.result:
		if err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.bus.Publish(topic, msg)
}
