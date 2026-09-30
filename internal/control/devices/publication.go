package devices

import (
	"context"
	"errors"
)

// PublicationStrategy declares who owns delivery. Production uses the durable
// outbox written by the enrollment/revocation transaction. In-process delivery
// is an explicit test/local strategy and reports failures to its caller.
type (
	PublicationStrategy interface {
		AfterCommit(context.Context, Event) error
	}
	TransactionalOutbox struct{}
)

func (TransactionalOutbox) AfterCommit(context.Context, Event) error { return nil }

type InProcessPublication struct{ Publisher Publisher }

func (p InProcessPublication) AfterCommit(ctx context.Context, e Event) error {
	if p.Publisher == nil {
		return errors.New("publisher is required")
	}

	return p.Publisher.Publish(ctx, e)
}

func WithPublicationStrategy(p PublicationStrategy) Option {
	return func(s *Service) {
		if p != nil {
			s.publication = p
		}
	}
}
