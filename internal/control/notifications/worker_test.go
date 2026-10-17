package notifications_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	"github.com/StasOkhrym/homeharbor/internal/platform/mail"
)

type deliveryQueue struct {
	delivery         notifications.Delivery
	found            bool
	claimErr         error
	outcome          notifications.Outcome
	finishContextErr error
	finishBounded    bool
}

func (q *deliveryQueue) Claim(context.Context) (notifications.Delivery, bool, error) {
	found := q.found
	q.found = false

	return q.delivery, found, q.claimErr
}

func (q *deliveryQueue) Finish(
	ctx context.Context,
	_ notifications.Delivery,
	outcome notifications.Outcome,
) error {
	q.outcome = outcome

	q.finishContextErr = ctx.Err()

	_, q.finishBounded = ctx.Deadline()

	return nil
}

type submitFunc func(context.Context, mail.Message) error

func (f submitFunc) Send(ctx context.Context, message mail.Message) error { return f(ctx, message) }
func workerFixture(t *testing.T) (*notifications.Codec, *deliveryQueue, notifications.Intent) {
	t.Helper()
	codec, intent := mailFixture(t)

	prepared, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	return codec, &deliveryQueue{
		delivery: notifications.Delivery{Prepared: prepared, LeaseToken: "test-lease", Attempt: 1},
		found:    true,
	}, intent
}

func TestDeliveryWorkerRendersAndAcknowledgesAcceptedMessage(t *testing.T) {
	codec, queue, intent := workerFixture(t)
	var submitted []mail.Message

	worker, err := notifications.NewWorker(
		queue,
		codec,
		submitFunc(func(_ context.Context, message mail.Message) error {
			submitted = append(submitted, message)
			return nil
		}),
		nil,
		func() time.Time { return intent.CreatedAt },
	)
	if err != nil {
		t.Fatal(err)
	}

	found, err := worker.DispatchOnce(t.Context())

	if err != nil || !found || queue.outcome != notifications.DeliverySent || len(submitted) != 1 ||
		submitted[0].To != intent.To ||
		!strings.Contains(submitted[0].Text, intent.Token) {
		t.Fatal("accepted message not rendered/acknowledged", err)
	}

	found, err = worker.DispatchOnce(t.Context())

	if err != nil || found || len(submitted) != 1 {
		t.Fatal("empty queue caused another submission", err)
	}
}

func TestDeliveryWorkerClassifiesFailuresWithoutLeakingPayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want notifications.Outcome
	}{
		{"temporary", mail.ErrTemporary, notifications.RetryDelivery},
		{"permanent", mail.ErrPermanent, notifications.PermanentFailure},
		{"invalid", mail.ErrInvalidMessage, notifications.InvalidPayload},
		{"unknown", errors.New("PRIVATE_PROVIDER_REPLY"), notifications.RetryDelivery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			codec, queue, intent := workerFixture(t)
			worker, err := notifications.NewWorker(
				queue,
				codec,
				submitFunc(func(context.Context, mail.Message) error { return tc.err }),
				nil,
				func() time.Time { return intent.CreatedAt },
			)
			if err != nil {
				t.Fatal(err)
			}

			if found, err := worker.DispatchOnce(
				t.Context(),
			); err != nil || !found ||
				queue.outcome != tc.want {
				t.Fatal("unsafe or incorrect provider error classification", err)
			}
		})
	}
}

func TestDeliveryWorkerDoesNotSendTamperedPayload(t *testing.T) {
	codec, queue, intent := workerFixture(t)
	queue.delivery.Ciphertext[len(queue.delivery.Ciphertext)-1] ^= 1

	worker, err := notifications.NewWorker(
		queue,
		codec,
		submitFunc(
			func(context.Context, mail.Message) error { t.Error("tampered payload reached SMTP"); return nil },
		),
		nil,
		func() time.Time { return intent.CreatedAt },
	)
	if err != nil {
		t.Fatal(err)
	}

	if found, err := worker.DispatchOnce(
		t.Context(),
	); err != nil || !found ||
		queue.outcome != notifications.InvalidPayload {
		t.Fatal("tampered payload not quarantined", err)
	}
}

func TestDeliveryWorkerReleasesLeaseAfterCancellation(t *testing.T) {
	codec, queue, intent := workerFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	worker, err := notifications.NewWorker(
		queue,
		codec,
		submitFunc(
			func(context.Context, mail.Message) error { cancel(); return mail.ErrTemporary },
		),
		nil,
		func() time.Time { return intent.CreatedAt },
	)
	if err != nil {
		t.Fatal(err)
	}

	if found, err := worker.DispatchOnce(
		ctx,
	); err != nil || !found || queue.outcome != notifications.RetryDelivery || queue.finishContextErr != nil ||
		!queue.finishBounded {
		t.Fatal("cancelled send left an unacknowledged or unbounded lease", err)
	}
}
