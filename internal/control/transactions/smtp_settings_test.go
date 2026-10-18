package transactions_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identitypg "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	notificationpg "github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
	transactionpg "github.com/StasOkhrym/homeharbor/internal/control/transactions"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
)

func TestPostgresSMTPTestRequiresRecentVerifiedOwnerAndIsSerialized(t *testing.T) {
	flow, store, pool, codec, owner, now := accountMailFixture(t)

	initial, err := flow.SMTPStatus(t.Context(), owner)

	if err != nil || !initial.Configured || !initial.RecipientVerified ||
		initial.Recipient != "owner@example.test" ||
		initial.Test.State != "never" {
		t.Fatal("initial mail status unavailable", err)
	}

	for _, change := range []func(*identity.Principal){
		func(p *identity.Principal) { p.Role = identity.RoleAdmin },
		func(p *identity.Principal) { p.AuthVersion++ },
		func(p *identity.Principal) { p.AuthenticatedAt = p.AuthenticatedAt.Add(-5 * time.Minute) },
	} {
		invalid := owner

		change(&invalid)

		if err := flow.SendSMTPTest(t.Context(), invalid); err == nil {
			t.Fatal("non-recent or non-owner test accepted")
		}
	}

	second, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(second.Close)

	hasher, err := identity.NewPasswordHasher(2)
	if err != nil {
		t.Fatal(err)
	}

	replica, err := workflows.NewAccountMail(
		transactionpg.NewAccountMailUnitOfWork(second),
		identitypg.New(second),
		hasher,
		codec,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	outcomes := make(chan error, 2)
	for _, service := range []*workflows.AccountMail{flow, replica} {
		wg.Go(func() { outcomes <- service.SendSMTPTest(t.Context(), owner) })
	}

	wg.Wait()
	close(outcomes)
	accepted, limited := 0, 0
	for err := range outcomes {
		if err == nil {
			accepted++
		} else if errors.Is(err, identity.ErrMailRateLimited) {
			limited++
		} else {
			t.Fatal("unexpected test result", err)
		}
	}

	if accepted != 1 || limited != 1 {
		t.Fatal("parallel mail test escaped owner serialization", accepted, limited)
	}

	state, err := flow.SMTPStatus(t.Context(), owner)

	if err != nil || state.Test.State != "pending" || state.Test.Attempts != 0 ||
		state.Test.CreatedAt == nil {
		t.Fatal("queued test not represented", err)
	}

	queue := notificationpg.New(pool)

	delivery, ok, err := queue.Claim(t.Context())

	if err != nil || !ok || delivery.Kind != notifications.SMTPTest {
		t.Fatal("encrypted test not claimable", err)
	}

	message, err := codec.Render(delivery.Prepared, *now)

	if err != nil || message.To != "owner@example.test" {
		t.Fatal("test did not use verified owner recipient", err)
	}

	// Queue acknowledgement only: this does not claim real SMTP delivery.
	if err := queue.Finish(t.Context(), delivery, notifications.DeliverySent); err != nil {
		t.Fatal(err)
	}

	state, err = flow.SMTPStatus(t.Context(), owner)

	if err != nil || state.Test.State != "sent" || state.Test.Attempts != 1 {
		t.Fatal("durable completion missing", err)
	}

	disabled, err := workflows.NewAccountMail(
		transactionpg.NewAccountMailUnitOfWork(pool),
		store,
		hasher,
		nil,
		func() time.Time { return *now },
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := disabled.SendSMTPTest(
		t.Context(),
		owner,
	); !errors.Is(
		err,
		workflows.ErrMailDisabled,
	) {
		t.Fatal("disabled test accepted", err)
	}

	state, err = disabled.SMTPStatus(t.Context(), owner)

	if err != nil || state.Configured || state.Test.State != "sent" {
		t.Fatal("disabled status erased historical test", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE admin_accounts SET email_verified_at=NULL WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	if err := flow.SendSMTPTest(
		t.Context(),
		owner,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("unverified recipient accepted", err)
	}

	admin := owner
	admin.Role = identity.RoleAdmin

	if _, err := flow.SMTPStatus(
		t.Context(),
		admin,
	); !errors.Is(
		err,
		identity.ErrInvalidCredential,
	) {
		t.Fatal("admin read SMTP settings", err)
	}
}

func TestPostgresSMTPTestQueueFailureIsSafeAndRetriable(t *testing.T) {
	flow, _, pool, _, owner, _ := accountMailFixture(t)

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries ADD CONSTRAINT reject_smtp_test CHECK (kind <> 'smtp_test')`,
	); err != nil {
		t.Fatal(err)
	}

	if err := flow.SendSMTPTest(
		t.Context(),
		owner,
	); !errors.Is(
		err,
		identity.ErrSecurityStateUnavailable,
	) {
		t.Fatal("queue failure was not safe", err)
	}

	state, err := flow.SMTPStatus(t.Context(), owner)

	if err != nil || state.Test.State != "never" {
		t.Fatal("failed test left a committed delivery", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`ALTER TABLE notification_deliveries DROP CONSTRAINT reject_smtp_test`,
	); err != nil {
		t.Fatal(err)
	}

	if err := flow.SendSMTPTest(t.Context(), owner); err != nil {
		t.Fatal("repaired test cannot retry", err)
	}
}
