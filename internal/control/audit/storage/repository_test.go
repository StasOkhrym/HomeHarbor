package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/migrations"
)

func TestPostgresAuditRedeliveryIsIdempotent(t *testing.T) {
	endpoint := os.Getenv("TEST_DATABASE_URL")
	if endpoint == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	pool, err := pgxpool.New(t.Context(), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("outbox-test-%d", time.Now().UnixNano())
	event := audit.Event{ID: id, OccurredAt: time.Now().UTC(), ActorType: "device", ActorID: "test", Action: "device.enrolled", TargetType: "device", TargetID: "test", Metadata: map[string]any{}}
	repository := New(pool)
	for range 2 {
		if err := repository.Write(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE event_id=$1`, id).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit redelivery created %d entries", count)
	}
}
