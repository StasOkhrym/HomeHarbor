package events

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	auditstorage "github.com/StasOkhrym/homeharbor/internal/control/audit/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func deliveryDB(t *testing.T, maxConns int32) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL required")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}

	schema := pgx.Identifier{fmt.Sprintf("delivery_%d", time.Now().UnixNano())}.Sanitize()

	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}

	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = maxConns

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")

		admin.Close()
	})

	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	_, err = pool.Exec(ctx, `INSERT INTO event_outbox(topic,payload,occurred_at) VALUES
 ('device.enrolled','{"type":"device.enrolled","aggregate_id":"device-1","occurred_at":"2026-09-30T12:00:00Z"}',now())`)
	if err != nil {
		t.Fatal(err)
	}

	return pool
}

func TestPostgresSingleConnectionAuditDelivery(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err != nil {
		t.Fatalf("one-connection delivery: %v", err)
	}

	var count int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_id='outbox:1'`).
		Scan(&count); err != nil ||
		count != 1 {
		t.Fatalf("audit count=%d err=%v", count, err)
	}
}

func TestPostgresRedeliveryExactlyOneAuditRecord(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()
	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET published_at=NULL WHERE id=1`,
	); err != nil {
		t.Fatal(err)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	var count int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_id='outbox:1'`).
		Scan(&count); err != nil ||
		count != 1 {
		t.Fatalf("duplicate audit rows=%d err=%v", count, err)
	}
}

func TestPostgresCompletionFailureRollsBackAudit(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	_, err := pool.Exec(
		ctx,
		`CREATE FUNCTION reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'completion unavailable'; END $$;
 CREATE TRIGGER reject_completion BEFORE UPDATE OF published_at ON event_outbox FOR EACH ROW EXECUTE FUNCTION reject_completion()`,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err == nil {
		t.Fatal("completion failure accepted")
	}

	var count int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).
		Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("uncommitted audit row count=%d err=%v", count, err)
	}
}

func TestPostgresTransientRetryPersisted(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	_, err := pool.Exec(
		ctx,
		`CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'secret-token-123'; END $$;
 CREATE TRIGGER reject_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_audit()`,
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err == nil {
		t.Fatal("audit failure ignored")
	}

	var attempts int
	var next, databaseNow time.Time
	var last string

	if err := pool.QueryRow(ctx, `SELECT attempts,next_attempt_at,last_error,now() FROM event_outbox WHERE id=1`).
		Scan(&attempts, &next, &last, &databaseNow); err != nil {
		t.Fatal(err)
	}

	if attempts != 1 || !next.After(databaseNow) || last == "" ||
		strings.Contains(last, "secret-token") {
		t.Fatalf(
			"unsafe or missing persisted retry: attempts=%d next=%v error=%q",
			attempts,
			next,
			last,
		)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("failed audit delivery reported ready")
	}

	if _, err := pool.Exec(
		ctx,
		`DROP TRIGGER reject_audit ON audit_events; UPDATE event_outbox SET next_attempt_at=now() WHERE id=1`,
	); err != nil {
		t.Fatal(err)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(ctx); err != nil {
		t.Fatalf("recovered delivery remains degraded: %v", err)
	}
}

func TestPostgresPoisonEventDegradesReadiness(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	if _, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET payload='{"schema_version":99,"event_id":"poison"}' WHERE id=1`,
	); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err != nil {
		t.Fatalf("poison row stopped dispatcher: %v", err)
	}

	var quarantined bool
	var attempts int

	if err := pool.QueryRow(ctx, `SELECT quarantined_at IS NOT NULL,attempts FROM event_outbox WHERE id=1`).
		Scan(&quarantined, &attempts); err != nil {
		t.Fatal(err)
	}

	if !quarantined || attempts != 1 {
		t.Fatalf("poison state quarantined=%v attempts=%d", quarantined, attempts)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("poison audit row reported ready")
	}
}

func TestInviteActorAndTargetAreNotDeviceByDefault(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	if _, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET topic='invite.approved', payload='{"type":"invite.approved","aggregate_id":"invite-1","occurred_at":"2026-09-30T12:00:00Z"}' WHERE id=1`,
	); err != nil {
		t.Fatal(err)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	var actorType, actorID, targetType, targetID string

	if err := pool.QueryRow(ctx, `SELECT actor_type,actor_id,target_type,target_id FROM audit_events`).
		Scan(&actorType, &actorID, &targetType, &targetID); err != nil {
		t.Fatal(err)
	}

	if actorType != "unknown" || actorID != "" || targetType != "invite" || targetID != "invite-1" {
		t.Fatalf("fabricated identities: %q %q %q %q", actorType, actorID, targetType, targetID)
	}
}

func TestPostgresTopicMismatchQuarantinesEvent(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	if _, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET topic='invite.approved' WHERE id=1`,
	); err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	var count int
	var quarantined bool

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `SELECT quarantined_at IS NOT NULL FROM event_outbox WHERE id=1`).
		Scan(&quarantined); err != nil {
		t.Fatal(err)
	}

	if count != 0 || !quarantined {
		t.Fatalf("topic mismatch projected=%d quarantined=%v", count, quarantined)
	}
}

func TestUnknownActionCannotBecomeTypedFact(t *testing.T) {
	_, err := FromDeviceEvent(
		devices.Event{Type: "device.unreviewed", AggregateID: "device-1", OccurredAt: time.Now()},
	)

	if err == nil {
		t.Fatal("unknown action accepted")
	}
}

func TestDispatcherReadyRequiresActiveWorker(t *testing.T) {
	pool := deliveryDB(t, 1)
	d := NewDispatcher(pool, auditstorage.New(pool), nil)
	ctx := context.Background()

	if err := d.Check(ctx); err != nil {
		t.Fatal(err)
	}

	if err := d.Ready(ctx); err == nil {
		t.Fatal("idle dispatcher reported ready")
	}

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- d.Run(runCtx) }()
	deadline := time.Now().Add(2 * time.Second)
	for d.Ready(ctx) != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if err := d.Ready(ctx); err != nil {
		cancel()
		<-done

		t.Fatalf("running dispatcher unready: %v", err)
	}

	cancel()

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if err := d.Ready(ctx); err == nil {
		t.Fatal("stopped dispatcher reported ready")
	}
}

func TestPostgresStalePendingAuditDegradesReadiness(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()
	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.Check(ctx); err != nil {
		t.Fatalf("fresh pending event degraded readiness: %v", err)
	}

	if _, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET occurred_at=now()-interval '121 seconds'`,
	); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("stale unattempted audit event reported ready")
	}

	if _, err := pool.Exec(ctx, `UPDATE event_outbox SET occurred_at=now()`); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(ctx); err != nil {
		t.Fatalf("fresh pending event did not recover readiness: %v", err)
	}
}

func TestPostgresDeliveryStatusCountsDurableRows(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `INSERT INTO event_outbox
 (topic,payload,occurred_at,attempts,next_attempt_at,quarantined_at,published_at) VALUES
 ('device.enrolled','{}',now()-interval '30 seconds',1,now()+interval '1 second',NULL,NULL),
 ('device.enrolled','{}',now()-interval '1 hour',1,NULL,now(),NULL),
 ('device.enrolled','{}',now()-interval '1 hour',1,NULL,NULL,now())`)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	status, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if status.Pending != 2 || status.Failed != 1 || status.Quarantined != 1 ||
		status.OldestPendingAge < 25*time.Second || status.OldestPendingAge > 35*time.Second {
		t.Fatalf("unexpected durable delivery status: %+v", status)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("failed and quarantined rows reported ready")
	}

	if _, err := pool.Exec(ctx, `UPDATE event_outbox SET occurred_at=now()+interval '1 hour'
 WHERE published_at IS NULL AND quarantined_at IS NULL`); err != nil {
		t.Fatal(err)
	}

	status, err = d.Status(ctx)

	if err != nil || status.OldestPendingAge != 0 {
		t.Fatalf("future timestamp must not produce negative age: status=%+v err=%v", status, err)
	}
}

func TestDecodeRejectsDisguisedLegacyPayload(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":null,"type":"device.enrolled","aggregate_id":"device-1","occurred_at":"2026-09-30T12:00:00Z"}`,
		`{"type":"device.enrolled","aggregate_id":"device-1","occurred_at":"2026-09-30T12:00:00Z","token":"private"}`,
	} {
		if _, err := Decode(1, []byte(body)); err == nil {
			t.Fatalf("disguised legacy payload accepted: %s", body)
		}
	}
}

func TestRetryBackoffCapsAtOneMinute(t *testing.T) {
	for _, tc := range []struct{ failures, want int }{{0, 1}, {1, 2}, {2, 4}, {3, 8}, {4, 16}, {5, 32}, {6, 60}, {20, 60}} {
		if got := retrySeconds(tc.failures); got != tc.want {
			t.Fatalf("failures=%d delay=%d want=%d", tc.failures, got, tc.want)
		}
	}
}

func TestPostgresMigrationPreservesPendingLegacyRow(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	before, err := os.ReadFile("../../../migrations/000013_outbox_delivery_state.down.sql")
	if err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile("../../../migrations/000013_outbox_delivery_state.up.sql")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, string(before)); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, string(after)); err != nil {
		t.Fatal(err)
	}

	var id int64
	var body []byte
	var pending bool

	if err := pool.QueryRow(ctx, `SELECT id,payload,published_at IS NULL FROM event_outbox`).
		Scan(&id, &body, &pending); err != nil {
		t.Fatal(err)
	}

	var old devices.Event

	if err := json.Unmarshal(body, &old); err != nil {
		t.Fatal(err)
	}

	if id != 1 || !pending || old.AggregateID != "device-1" || old.Type != "device.enrolled" {
		t.Fatalf("legacy row changed: id=%d pending=%v event=%#v", id, pending, old)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejectsTrailingJSONValue(t *testing.T) {
	body := []byte(
		`{"type":"device.enrolled","aggregate_id":"device-1","occurred_at":"2026-09-30T12:00:00Z"} {"type":"device.revoked"}`,
	)

	if _, err := Decode(1, body); err == nil {
		t.Fatal("trailing JSON value accepted")
	}
}

type blockingRollback struct{}

func (blockingRollback) Rollback(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }

func TestRollbackCleanupHasDeadline(t *testing.T) {
	started := time.Now()

	rollbackBounded(blockingRollback{}, 10*time.Millisecond)

	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("rollback blocked for %v", elapsed)
	}
}

func TestPostgresCommitFailurePersistsRetryAndDegradesReadiness(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `CREATE TABLE audit_action_gate(action text PRIMARY KEY);
 ALTER TABLE audit_events ADD CONSTRAINT audit_action_gate_fk
 FOREIGN KEY(action) REFERENCES audit_action_gate(action) DEFERRABLE INITIALLY DEFERRED`)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err == nil {
		t.Fatal("deferred audit constraint failure ignored")
	}

	var attempts, auditCount int
	var last string
	var next, databaseNow time.Time
	var pending bool

	err = pool.QueryRow(ctx, `SELECT attempts,COALESCE(last_error,''),
 COALESCE(next_attempt_at,'epoch'::timestamptz),published_at IS NULL,now()
 FROM event_outbox WHERE id=1`).Scan(&attempts, &last, &next, &pending, &databaseNow)
	if err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).
		Scan(&auditCount); err != nil {
		t.Fatal(err)
	}

	if attempts != 1 || last != "audit projection failed" || !next.After(databaseNow) || !pending ||
		auditCount != 0 {
		t.Fatalf(
			"commit failure state attempts=%d last=%q next=%v pending=%v audit=%d",
			attempts,
			last,
			next,
			pending,
			auditCount,
		)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("commit failure reported ready")
	}

	if _, err := pool.Exec(ctx, `ALTER TABLE audit_events DROP CONSTRAINT audit_action_gate_fk;
 UPDATE event_outbox SET next_attempt_at=now() WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if err := NewDispatcher(pool, auditstorage.New(pool), nil).DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_id='outbox:1'`).
		Scan(&auditCount); err != nil ||
		auditCount != 1 {
		t.Fatalf("retry audit rows=%d err=%v", auditCount, err)
	}

	if err := d.Check(ctx); err != nil {
		t.Fatalf("recovered commit failure reported unready: %v", err)
	}
}

func TestPostgresQuarantineCommitFailurePersistsRetry(t *testing.T) {
	pool := deliveryDB(t, 1)
	ctx := context.Background()

	_, err := pool.Exec(
		ctx,
		`UPDATE event_outbox SET payload='{"schema_version":99,"event_id":"poison"}' WHERE id=1;
 CREATE FUNCTION reject_quarantine_commit() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
  IF NEW.quarantined_at IS NOT NULL THEN RAISE EXCEPTION 'sensitive-marker'; END IF;
  RETURN NEW;
 END $$;
 CREATE CONSTRAINT TRIGGER reject_quarantine_commit AFTER UPDATE ON event_outbox
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_quarantine_commit()`,
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NewDispatcher(pool, auditstorage.New(pool), nil)

	if err := d.DispatchBatch(ctx); err == nil {
		t.Fatal("quarantine commit failure ignored")
	}

	var attempts int
	var last string
	var next, databaseNow time.Time
	var quarantined bool

	err = pool.QueryRow(ctx, `SELECT attempts,COALESCE(last_error,''),
 COALESCE(next_attempt_at,'epoch'::timestamptz),quarantined_at IS NOT NULL,now()
 FROM event_outbox WHERE id=1`).Scan(&attempts, &last, &next, &quarantined, &databaseNow)
	if err != nil {
		t.Fatal(err)
	}

	if attempts != 1 || last == "" || strings.Contains(last, "sensitive-marker") ||
		!next.After(databaseNow) ||
		quarantined {
		t.Fatalf(
			"quarantine commit failure attempts=%d last=%q next=%v quarantined=%v",
			attempts,
			last,
			next,
			quarantined,
		)
	}

	if err := d.Check(ctx); err == nil {
		t.Fatal("failed quarantine reported ready")
	}

	if _, err := pool.Exec(ctx, `DROP TRIGGER reject_quarantine_commit ON event_outbox;
 UPDATE event_outbox SET next_attempt_at=now() WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	if err := d.DispatchBatch(ctx); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `SELECT quarantined_at IS NOT NULL FROM event_outbox WHERE id=1`).
		Scan(&quarantined); err != nil ||
		!quarantined {
		t.Fatalf("retry did not quarantine poison: quarantined=%v err=%v", quarantined, err)
	}
}
