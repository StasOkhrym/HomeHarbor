package events

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type outboxProbe struct {
	failure error
	ids     []string
}

func (p *outboxProbe) Publish(_ context.Context, _ string, msg *message.Message) error {
	p.ids = append(p.ids, msg.UUID)
	return p.failure
}

func outboxTestDB(t *testing.T) *pgxpool.Pool {
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
	schema := pgx.Identifier{fmt.Sprintf("outbox_test_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	_, err = pool.Exec(ctx, `CREATE TABLE event_outbox (
		id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		topic text NOT NULL,payload jsonb NOT NULL,published_at timestamptz,
		attempts integer NOT NULL DEFAULT 0,last_error text);
		INSERT INTO event_outbox(topic,payload) VALUES('device.enrolled','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestPostgresOutboxKeepsUnacknowledgedRowsForStableRedelivery(t *testing.T) {
	pool := outboxTestDB(t)
	probe := &outboxProbe{failure: errors.New("audit commit unavailable")}
	ctx := context.Background()
	if err := dispatchOutboxBatch(ctx, pool, probe); !errors.Is(err, probe.failure) {
		t.Fatalf("error = %v", err)
	}
	var pending bool
	if err := pool.QueryRow(ctx, `SELECT published_at IS NULL FROM event_outbox`).
		Scan(&pending); err != nil ||
		!pending {
		t.Fatalf("unacknowledged row lost: pending=%v error=%v", pending, err)
	}
	probe.failure = nil
	if err := dispatchOutboxBatch(ctx, pool, probe); err != nil {
		t.Fatal(err)
	}
	if len(probe.ids) != 2 || probe.ids[0] != probe.ids[1] || probe.ids[0] != "outbox:1" {
		t.Fatalf("retry identity changed: %v", probe.ids)
	}
	if err := pool.QueryRow(ctx, `SELECT published_at IS NULL FROM event_outbox`).
		Scan(&pending); err != nil ||
		pending {
		t.Fatalf("acknowledged row not marked: pending=%v error=%v", pending, err)
	}
}

func TestPostgresOutboxCriticalFailureStopsDispatcher(t *testing.T) {
	pool := outboxTestDB(t)
	want := errors.New("critical durable consumer stopped")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := RunOutboxDispatcher(ctx, pool, &outboxProbe{failure: want}, nil)
	if !errors.Is(err, want) {
		t.Fatalf("dispatcher hid critical failure: %v", err)
	}
}
