package storage

import (
	"context"
	"fmt"
	"os"
	"slices"
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

func TestPostgresAuditFacetedFilters(t *testing.T) {
	pool := auditQueryDB(t)
	repo := New(pool)
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	events := []audit.Event{
		{
			OccurredAt: now.Add(-time.Hour),
			ActorType:  "admin",
			ActorID:    "owner",
			Action:     "admin.login",
			TargetType: "session",
			TargetID:   "session-a",
			Metadata:   map[string]any{"success": true, "outcome": "failure"},
		},
		{
			OccurredAt: now.Add(-30 * time.Minute),
			ActorType:  "admin",
			ActorID:    "other",
			Action:     "admin.login",
			TargetType: "session",
			TargetID:   "session-b",
			Metadata:   map[string]any{"success": false, "outcome": "success"},
		},
		{
			OccurredAt: now.Add(-23 * time.Hour),
			ActorType:  "admin",
			ActorID:    "owner",
			Action:     "device.enrolled",
			TargetType: "device",
			TargetID:   "phone",
			Metadata:   map[string]any{"outcome": "success"},
		},
		{
			OccurredAt: now.Add(-2 * time.Hour),
			ActorType:  "admin",
			ActorID:    "owner",
			Action:     "device.revoked",
			TargetType: "device",
			TargetID:   "laptop",
			Metadata:   map[string]any{"success": false},
		},
		{
			OccurredAt: now.Add(-48 * time.Hour),
			ActorType:  "device",
			ActorID:    "phone",
			Action:     "device.credential_rotated",
			TargetType: "device",
			TargetID:   "phone",
			Metadata:   map[string]any{},
		},
		{
			OccurredAt: now,
			ActorType:  "system",
			ActorID:    "worker",
			Action:     "unregistered.event",
			TargetType: "system",
			TargetID:   "worker",
			Metadata:   map[string]any{"success": "true"},
		},
	}
	events = append(
		events,
		audit.Event{
			OccurredAt: now.Add(-6 * time.Hour),
			ActorType:  "admin",
			ActorID:    "owner",
			Action:     "invite.approved",
			TargetType: "invite",
			TargetID:   "invite-a",
			Metadata:   map[string]any{"outcome": "success"},
		},
	)

	for _, event := range events {
		if err := repo.Write(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name  string
		query audit.Query
		want  []string
	}{
		{
			"intersection",
			audit.Query{
				Category: "devices",
				Outcome:  "success",
				ActorID:  "owner",
				DeviceID: "phone",
				Since:    now.Add(-24 * time.Hour),
				Until:    now,
			},
			[]string{"device.enrolled"},
		},
		{
			"boolean wins over string",
			audit.Query{Category: "security", Outcome: "failure"},
			[]string{"admin.login"},
		},
		{
			"device as actor or target",
			audit.Query{DeviceID: "phone"},
			[]string{"device.credential_rotated", "device.enrolled"},
		},
		{
			"unknown does not become success",
			audit.Query{Outcome: "unknown"},
			[]string{"unregistered.event", "device.credential_rotated"},
		},
		{
			"unregistered system event",
			audit.Query{Category: "system"},
			[]string{"unregistered.event"},
		},
		{"parameterized action", audit.Query{Action: "' OR true --"}, nil},
		{
			"exclusive time bound",
			audit.Query{Since: now, Until: now.Add(time.Second)},
			[]string{"unregistered.event"},
		},
	}
	cases = append(cases,
		struct {
			name  string
			query audit.Query
			want  []string
		}{"access category", audit.Query{Category: "access"}, []string{"invite.approved"}},
		struct {
			name  string
			query audit.Query
			want  []string
		}{"empty administrators category", audit.Query{Category: "administrators"}, nil},
	)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := repo.ListRecords(t.Context(), tc.query)
			if err != nil {
				t.Fatal(err)
			}

			got := make([]string, 0, len(rows))
			for _, row := range rows {
				got = append(got, row.Event.Action)
			}

			if !slices.Equal(got, tc.want) {
				t.Fatalf("actions=%v want=%v", got, tc.want)
			}
			if tc.name == "boolean wins over string" && rows[0].Event.ActorID != "other" {
				t.Fatal("false success must win over outcome success")
			}
		})
	}

	for _, q := range []audit.Query{{Category: "' OR true --"}, {Outcome: "maybe"}, {Since: now, Until: now.Add(-time.Hour)}} {
		if _, err := repo.ListRecords(t.Context(), q); err == nil {
			t.Fatal("invalid facet accepted at storage boundary")
		}
	}
}

func TestPostgresAuditFacetsRetainHistoricIdentities(t *testing.T) {
	pool := auditQueryDB(t)
	repository := New(pool)
	for _, event := range []audit.Event{
		{OccurredAt: time.Now(), ActorType: "admin", ActorID: "a-1", Action: "device.revoked", TargetType: "device", TargetID: "deleted-device", Metadata: map[string]any{"actor_name": "Olena", "target_name": "Old Mac"}},
		{OccurredAt: time.Now(), ActorType: "admin", ActorID: "a-1", Action: "device.revoked", TargetType: "device", TargetID: "deleted-device", Metadata: map[string]any{"actor_name": "Olena", "target_name": "Kitchen Mac"}},
	} {
		if err := repository.Write(t.Context(), event); err != nil {
			t.Fatal(err)
		}
	}

	facets, err := repository.ListFacets(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if len(facets.Actors) != 1 || facets.Actors[0].Name != "Olena" || len(facets.Devices) != 1 ||
		facets.Devices[0].ID != "deleted-device" ||
		facets.Devices[0].Name != "Kitchen Mac" {
		t.Fatalf("lost historical identity facets: %+v", facets)
	}
}
