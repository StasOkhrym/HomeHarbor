package storage_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func mailSQLFixture(
	t *testing.T,
) (*storage.Repository, *storage.Repository, *pgxpool.Pool, *notifications.Codec, notifications.Intent) {
	t.Helper()
	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	other, err := pgxpool.NewWithConfig(t.Context(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(other.Close)

	codec, err := notifications.NewCodec(
		bytes.Repeat([]byte{7}, 32),
		"https://control.example.test",
	)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Add(-time.Minute)
	intent := notifications.Intent{
		ID:        uuid.NewString(),
		AccountID: identity.OwnerAccountID,
		Kind:      notifications.PasswordReset,
		To:        "owner@example.test",
		Token:     base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}

	return storage.New(pool), storage.New(other), pool, codec, intent
}

func prepare(
	t *testing.T,
	codec *notifications.Codec,
	intent notifications.Intent,
) notifications.Prepared {
	t.Helper()

	p, err := codec.Prepare(intent)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestPostgresMailEnqueueIsIdempotentEncryptedAndTransactional(t *testing.T) {
	store, _, pool, codec, intent := mailSQLFixture(t)

	first := prepare(t, codec, intent)

	if err := store.Enqueue(t.Context(), first); err != nil {
		t.Fatal(err)
	}

	if err := store.Enqueue(t.Context(), prepare(t, codec, intent)); err != nil {
		t.Fatal("logical retry rejected", err)
	}

	var count int
	var ciphertext []byte

	if err := pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM notification_deliveries WHERE id=$1),private_payload FROM notification_deliveries WHERE id=$1`, first.ID).
		Scan(&count, &ciphertext); err != nil {
		t.Fatal(err)
	}

	if count != 1 || !bytes.Equal(ciphertext, first.Ciphertext) ||
		bytes.Contains(ciphertext, []byte(intent.To)) ||
		bytes.Contains(ciphertext, []byte(intent.Token)) {
		t.Fatal("logical delivery duplicated, changed or stored plaintext")
	}

	changed := intent

	changed.Token = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))

	if err := store.Enqueue(
		t.Context(),
		prepare(t, codec, changed),
	); !errors.Is(
		err,
		notifications.ErrLogicalConflict,
	) {
		t.Fatal("logical ID overwritten by changed contents", err)
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })

	if _, err := tx.Exec(
		t.Context(),
		`UPDATE admin_accounts SET email='rollback@example.test' WHERE account_id=$1`,
		identity.OwnerAccountID,
	); err != nil {
		t.Fatal(err)
	}

	pending := intent
	pending.ID = uuid.NewString()

	if err := storage.Bind(tx).Enqueue(t.Context(), prepare(t, codec, pending)); err != nil {
		t.Fatal(err)
	}

	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	var absent bool

	if err := pool.QueryRow(t.Context(), `SELECT NOT EXISTS(SELECT 1 FROM notification_deliveries WHERE id=$1) AND (SELECT email IS NULL FROM admin_accounts WHERE account_id=$2)`, pending.ID, identity.OwnerAccountID).
		Scan(&absent); err != nil ||
		!absent {
		t.Fatal("mail/account mutation escaped transaction", err)
	}
}

func TestPostgresMailLeasesFenceStaleAcknowledgementsAndRetry(t *testing.T) {
	store, replica, pool, codec, intent := mailSQLFixture(t)

	prepared := prepare(t, codec, intent)

	if err := store.Enqueue(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}

	claimed := make(chan notifications.Delivery, 12)
	var group sync.WaitGroup
	for range 12 {
		group.Go(func() {
			delivery, found, err := replica.Claim(t.Context())
			if err != nil {
				t.Error(err)
			}

			if found {
				claimed <- delivery
			}
		})
	}

	group.Wait()
	close(claimed)
	var deliveries []notifications.Delivery
	for delivery := range claimed {
		deliveries = append(deliveries, delivery)
	}

	if len(deliveries) != 1 || deliveries[0].Attempt != 1 {
		t.Fatal("duplicate claim", len(deliveries))
	}

	first := deliveries[0]

	if _, err := codec.Render(first.Prepared, time.Now()); err != nil {
		t.Fatal("persisted ciphertext unusable", err)
	}

	if err := store.Finish(t.Context(), first, notifications.RetryDelivery); err != nil {
		t.Fatal(err)
	}

	if _, found, err := replica.Claim(t.Context()); err != nil || found {
		t.Fatal("retry ignored backoff", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET next_attempt_at=now()-interval '1 second' WHERE id=$1`,
		prepared.ID,
	); err != nil {
		t.Fatal(err)
	}

	second, found, err := replica.Claim(t.Context())

	if err != nil || !found || second.Attempt != 2 || first.LeaseToken == second.LeaseToken {
		t.Fatal("retry claim missing or unfenced", err)
	}

	if err := store.Finish(
		t.Context(),
		first,
		notifications.DeliverySent,
	); !errors.Is(
		err,
		notifications.ErrLeaseLost,
	) {
		t.Fatal("old worker acknowledged another lease", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET leased_until=now()-interval '1 second' WHERE id=$1`,
		prepared.ID,
	); err != nil {
		t.Fatal(err)
	}

	third, found, err := store.Claim(t.Context())

	if err != nil || !found || third.Attempt != 3 {
		t.Fatal("abandoned delivery not reclaimed", err)
	}

	if err := replica.Finish(
		t.Context(),
		second,
		notifications.DeliverySent,
	); !errors.Is(
		err,
		notifications.ErrLeaseLost,
	) {
		t.Fatal("expired worker acknowledged reclaimed lease", err)
	}

	if err := replica.Finish(t.Context(), third, notifications.DeliverySent); err != nil {
		t.Fatal(err)
	}

	if err := store.Enqueue(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}

	if _, found, err := store.Claim(t.Context()); err != nil || found {
		t.Fatal("idempotent enqueue resurrected a sent message", err)
	}

	var scrubbed bool

	if err := pool.QueryRow(t.Context(), `SELECT status='sent' AND private_payload IS NULL AND lease_token IS NULL FROM notification_deliveries WHERE id=$1`, prepared.ID).
		Scan(&scrubbed); err != nil ||
		!scrubbed {
		t.Fatal("sent payload retained", err)
	}
}

func TestPostgresMailExpiryAndFinalAttemptScrubPrivatePayloads(t *testing.T) {
	store, _, pool, codec, intent := mailSQLFixture(t)

	prepared := prepare(t, codec, intent)

	if err := store.Enqueue(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET expires_at=created_at+interval '1 second' WHERE id=$1`,
		prepared.ID,
	); err != nil {
		t.Fatal(err)
	}

	if _, found, err := store.Claim(t.Context()); err != nil || found {
		t.Fatal("expired message claimed", err)
	}

	next := intent
	next.ID = uuid.NewString()

	if err := store.Enqueue(t.Context(), prepare(t, codec, next)); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET attempts=7 WHERE id=$1`,
		next.ID,
	); err != nil {
		t.Fatal(err)
	}

	delivery, found, err := store.Claim(t.Context())

	if err != nil || !found || delivery.Attempt != 8 {
		t.Fatal("last attempt not acquired", err)
	}

	if err := store.Finish(t.Context(), delivery, notifications.RetryDelivery); err != nil {
		t.Fatal(err)
	}

	var scrubbed int

	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_deliveries WHERE private_payload IS NULL AND status IN ('expired','failed')`).
		Scan(&scrubbed); err != nil ||
		scrubbed != 2 {
		t.Fatal("terminal private payloads retained", scrubbed, err)
	}

	if _, found, err := store.Claim(t.Context()); err != nil || found {
		t.Fatal("exhausted message retried", err)
	}
}

func TestPostgresMailAbandonedFinalAttemptBecomesTerminal(t *testing.T) {
	store, _, pool, codec, intent := mailSQLFixture(t)

	prepared := prepare(t, codec, intent)

	if err := store.Enqueue(t.Context(), prepared); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET attempts=7 WHERE id=$1`,
		prepared.ID,
	); err != nil {
		t.Fatal(err)
	}

	delivery, found, err := store.Claim(t.Context())

	if err != nil || !found || delivery.Attempt != 8 {
		t.Fatal("last attempt not claimed", err)
	}

	if _, err := pool.Exec(
		t.Context(),
		`UPDATE notification_deliveries SET leased_until=now()-interval '1 second' WHERE id=$1`,
		prepared.ID,
	); err != nil {
		t.Fatal(err)
	}

	if _, found, err := store.Claim(t.Context()); err != nil || found {
		t.Fatal("exhausted abandoned message claimed again", err)
	}

	var terminal bool

	if err := pool.QueryRow(t.Context(), `SELECT status='failed' AND private_payload IS NULL AND lease_token IS NULL FROM notification_deliveries WHERE id=$1`, prepared.ID).
		Scan(&terminal); err != nil ||
		!terminal {
		t.Fatal("abandoned last attempt remained pending with private payload", err)
	}
}

func TestPostgresMailCancellationFencesClaimedDelivery(t *testing.T) {
	store, replica, pool, codec, intent := mailSQLFixture(t)

	if err := store.Enqueue(t.Context(), prepare(t, codec, intent)); err != nil {
		t.Fatal(err)
	}

	delivery, found, err := store.Claim(t.Context())

	if err != nil || !found {
		t.Fatal(err)
	}

	if err := replica.CancelPending(t.Context(), intent.AccountID, intent.Kind); err != nil {
		t.Fatal(err)
	}

	if err := store.Finish(
		t.Context(),
		delivery,
		notifications.DeliverySent,
	); !errors.Is(
		err,
		notifications.ErrLeaseLost,
	) {
		t.Fatal("obsolete worker acknowledged a cancelled delivery", err)
	}

	var private bool

	if err := pool.QueryRow(t.Context(), `SELECT status='cancelled' AND private_payload IS NULL AND lease_token IS NULL AND completed_at IS NOT NULL FROM notification_deliveries WHERE id=$1`, intent.ID).
		Scan(&private); err != nil ||
		!private {
		t.Fatal("cancelled secret payload retained", err)
	}
}
