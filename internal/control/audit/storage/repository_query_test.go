package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func auditQueryDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	endpoint := os.Getenv("TEST_DATABASE_URL")
	if endpoint == "" {
		t.Skip("TEST_DATABASE_URL required")
	}

	ctx := t.Context()
	admin, err := pgxpool.New(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}

	schema := pgx.Identifier{fmt.Sprintf("audit_query_%d", time.Now().UnixNano())}.Sanitize()

	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}

	config, err := pgxpool.ParseConfig(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
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

	return pool
}

func TestPostgresDirectAuthEventsHaveDistinctRecordIDs(t *testing.T) {
	pool := auditQueryDB(t)
	repository := New(pool)
	event := audit.Event{
		OccurredAt: time.Now(),
		ActorType:  "admin",
		ActorID:    "",
		Action:     "admin.login",
		TargetType: "session",
		TargetID:   "",
		Metadata:   map[string]any{"success": true},
	}
	for range 2 {
		if err := repository.Write(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}

	records, err := repository.ListRecords(t.Context(), audit.Query{})
	if err != nil {
		t.Fatal(err)
	}

	if len(records) != 2 || records[0].RecordID <= records[1].RecordID ||
		records[0].Event.ID != "" || records[1].Event.ID != "" {
		t.Fatalf("direct audit identities: %+v", records)
	}
}

func TestPostgresAuditQueryClampsAndFilters(t *testing.T) {
	pool := auditQueryDB(t)

	_, err := pool.Exec(t.Context(), `INSERT INTO audit_events
 (occurred_at,actor_type,actor_id,action,target_type,target_id,metadata)
 SELECT now(),'admin','','admin.login','session','target-a','{}'::jsonb
 FROM generate_series(1,205)`)
	if err != nil {
		t.Fatal(err)
	}

	repository := New(pool)

	defaultRows, err := repository.ListRecords(t.Context(), audit.Query{})

	if err != nil || len(defaultRows) != 100 {
		t.Fatalf("default window rows=%d err=%v", len(defaultRows), err)
	}

	clamped, err := repository.ListRecords(t.Context(), audit.Query{Limit: 999})

	if err != nil || len(clamped) != 200 {
		t.Fatalf("maximum window rows=%d err=%v", len(clamped), err)
	}

	older, err := repository.ListRecords(t.Context(), audit.Query{
		Limit: 3, BeforeID: defaultRows[0].RecordID, Action: "admin.login", TargetID: "target-a",
	})

	if err != nil || len(older) != 3 || older[0].RecordID >= defaultRows[0].RecordID {
		t.Fatalf("filtered history rows=%+v err=%v", older, err)
	}

	missing, err := repository.ListRecords(t.Context(), audit.Query{Action: "device.revoked"})

	if err != nil || len(missing) != 0 {
		t.Fatalf("unexpected filtered rows=%+v err=%v", missing, err)
	}
}

func TestPostgresRecentWindowFindsLowerIDCommittedLater(t *testing.T) {
	pool := auditQueryDB(t)
	ctx := t.Context()
	repository := New(pool)

	lowTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lowTx.Rollback(context.Background()) }()

	var lowID int64

	if err := lowTx.QueryRow(ctx, `INSERT INTO audit_events
 (occurred_at,actor_type,actor_id,action,target_type,target_id,metadata)
 VALUES(now(),'admin','','admin.login','session','low','{}'::jsonb) RETURNING id`).Scan(&lowID); err != nil {
		t.Fatal(err)
	}

	var highID int64

	if err := pool.QueryRow(ctx, `INSERT INTO audit_events
 (occurred_at,actor_type,actor_id,action,target_type,target_id,metadata)
 VALUES(now(),'admin','','admin.login','session','high','{}'::jsonb) RETURNING id`).Scan(&highID); err != nil {
		t.Fatal(err)
	}

	first, err := repository.ListRecords(ctx, audit.Query{Limit: 100})

	if err != nil || len(first) != 1 || first[0].RecordID != highID {
		t.Fatalf("first committed window=%+v err=%v", first, err)
	}

	if err := lowTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	second, err := repository.ListRecords(ctx, audit.Query{Limit: 100})

	if err != nil || len(second) != 2 || second[0].RecordID != highID ||
		second[1].RecordID != lowID {
		t.Fatalf("late lower-ID commit missing from recent window=%+v err=%v", second, err)
	}
}
