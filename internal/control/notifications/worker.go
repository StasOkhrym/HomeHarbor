package notifications

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
)

// DeliveryQueue owns durable retry scheduling and fenced acknowledgements.
// Claim must release its database transaction before returning.
type DeliveryQueue interface {
	Claim(context.Context) (Delivery, bool, error)
	Finish(context.Context, Delivery, Outcome) error
}

type Sender interface {
	Send(context.Context, mail.Message) error
}

type Worker struct {
	queue  DeliveryQueue
	codec  *Codec
	sender Sender
	logger *slog.Logger
	now    func() time.Time
}

func NewWorker(
	queue DeliveryQueue,
	codec *Codec,
	sender Sender,
	logger *slog.Logger,
	now func() time.Time,
) (*Worker, error) {
	if queue == nil || codec == nil || sender == nil {
		return nil, ErrUnavailable
	}

	if logger == nil {
		logger = slog.Default()
	}

	if now == nil {
		now = time.Now
	}

	return &Worker{queue: queue, codec: codec, sender: sender, logger: logger, now: now}, nil
}

// DispatchOnce submits one leased message without holding SQL locks during SMTP.
// Delivery is at least once: a crash after acceptance and before Finish may resend
// the same logical Message-ID. Account tokens remain single use.
func (w *Worker) DispatchOnce(ctx context.Context) (bool, error) {
	claimCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	delivery, found, err := w.queue.Claim(claimCtx)
	cancel()
	if err != nil {
		return false, ErrUnavailable
	}
	if !found {
		return false, nil
	}

	outcome := InvalidPayload

	message, err := w.codec.Render(delivery.Prepared, w.now())
	if err == nil {
		sendCtx, stop := context.WithTimeout(ctx, 30*time.Second)
		err = w.sender.Send(sendCtx, message)
		stop()
		switch {
		case err == nil:
			outcome = DeliverySent
		case errors.Is(err, mail.ErrInvalidMessage):
			outcome = InvalidPayload
		case errors.Is(err, mail.ErrPermanent):
			outcome = PermanentFailure
		default:
			outcome = RetryDelivery
		}
	}

	cleanupCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer stop()

	if err = w.queue.Finish(cleanupCtx, delivery, outcome); err != nil {
		if errors.Is(err, ErrLeaseLost) {
			return true, ErrLeaseLost
		}

		return true, ErrUnavailable
	}

	return true, nil
}

func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil {
			return nil
		}

		found, err := w.DispatchOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.logger.Warn("mail delivery state unavailable; retry scheduled")
		}

		if found && err == nil {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
