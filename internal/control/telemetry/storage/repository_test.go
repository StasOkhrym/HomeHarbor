package storage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry/storage"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	"github.com/StasOkhrym/homeharbor/internal/testutil"
)

func TestPostgresTelemetryFencesReconnectsAcrossReplicas(t *testing.T) {
	poolA := testutil.Postgres(t)
	testutil.Device(t, poolA, "gateway-1", "gateway")
	testutil.Device(t, poolA, "client-1", "client")
	poolB, err := pgxpool.NewWithConfig(t.Context(), poolA.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer poolB.Close()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	allow := func(_ context.Context, reporter devices.Device, subject string) (bool, error) {
		return reporter.ID == "gateway-1" && subject == "client-1", nil
	}
	repoA, repoB := storage.New(poolA), storage.New(poolB)
	a, b := telemetry.NewService(
		repoA,
		allow,
		func() time.Time { return now },
	), telemetry.NewService(
		repoB,
		allow,
		func() time.Time { return now },
	)
	device := devices.Device{
		ID:     "gateway-1",
		Role:   devices.RoleGateway,
		Status: devices.StatusActive,
	}
	first, err := a.Begin(t.Context(), device)
	if err != nil {
		t.Fatal(err)
	}
	report := protocol.TelemetryReport{
		Generation:      first.Generation,
		Sequence:        1,
		RuntimeID:       "bc6603d1-5985-45d3-a22b-756ff04e8800",
		State:           protocol.RuntimeRunning,
		AppliedRevision: 7,
		Observations: []protocol.PeerObservation{
			{DeviceID: "gateway-1"},
			{
				DeviceID:          "client-1",
				RXBytes:           10,
				TXBytes:           20,
				LastHandshakeUnix: now.Add(-time.Second).Unix(),
				Path:              protocol.PathRelay,
				Endpoint:          "127.0.0.1:51820",
			},
		},
	}
	if err := a.Report(t.Context(), first, report); err != nil {
		t.Fatal(err)
	}
	if err := a.Report(t.Context(), first, report); !errors.Is(err, telemetry.ErrStaleReport) {
		t.Fatalf("replay accepted: %v", err)
	}
	second, err := b.Begin(t.Context(), device)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation <= first.Generation {
		t.Fatal("generation did not advance across replicas")
	}
	report.Sequence = 100
	if err := a.Report(t.Context(), first, report); !errors.Is(err, telemetry.ErrStaleReport) {
		t.Fatalf("old replica session accepted: %v", err)
	}
	report.Generation, report.Sequence = second.Generation, 1
	report.Observations[1].RXBytes = 30
	if err := b.Report(t.Context(), second, report); err != nil {
		t.Fatal(err)
	}
	rows, err := repoA.Latest(t.Context(), 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("observations=%d", len(rows))
	}
	for _, row := range rows {
		if row.Generation != second.Generation || row.RuntimeID != report.RuntimeID ||
			!row.ObservedAt.Equal(now) {
			t.Fatalf("wrong server fact: %+v", row)
		}
		if row.SubjectDeviceID == "client-1" && row.Sample.RXBytes != 30 {
			t.Fatalf("stale report overwrote observation: %+v", row)
		}
		if row.CurrentState(now.Add(90*time.Second)) != "unknown" {
			t.Fatal("silence became a claim about current VPN state")
		}
	}
	report.Sequence = 2
	report.State = protocol.RuntimeStopped
	report.Observations = report.Observations[:1]
	if err := b.Report(t.Context(), second, report); err != nil {
		t.Fatal(err)
	}
	rows, err = repoA.Latest(t.Context(), 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].CurrentState(now) != "stopped" {
		t.Fatalf("explicit stop/full replacement missing: %+v", rows)
	}
}

func TestPostgresTelemetryRejectsForeignSubjects(t *testing.T) {
	pool := testutil.Postgres(t)

	testutil.Device(t, pool, "client-1", "client")
	testutil.Device(t, pool, "foreign", "client")
	repository := storage.New(pool)
	service := telemetry.NewService(
		repository,
		func(context.Context, devices.Device, string) (bool, error) { return false, nil },
		time.Now,
	)

	session, err := service.Begin(
		t.Context(),
		devices.Device{ID: "client-1", Role: devices.RoleClient, Status: devices.StatusActive},
	)
	if err != nil {
		t.Fatal(err)
	}

	report := protocol.TelemetryReport{
		Generation:   session.Generation,
		Sequence:     1,
		RuntimeID:    "bc6603d1-5985-45d3-a22b-756ff04e8800",
		State:        protocol.RuntimeRunning,
		Observations: []protocol.PeerObservation{{DeviceID: "foreign"}},
	}

	if err := service.Report(
		t.Context(),
		session,
		report,
	); !errors.Is(
		err,
		telemetry.ErrUnauthorized,
	) {
		t.Fatalf("client forged foreign subject: %v", err)
	}

	rows, err := repository.Latest(t.Context(), 200)

	if err != nil || len(rows) != 0 {
		t.Fatalf("partial unauthorized write: %+v %v", rows, err)
	}

	testutil.Device(t, pool, "gateway-1", "gateway")

	gateway, err := service.Begin(
		t.Context(),
		devices.Device{ID: "gateway-1", Role: devices.RoleGateway, Status: devices.StatusActive},
	)
	if err != nil {
		t.Fatal(err)
	}

	report.Generation = gateway.Generation
	report.Observations = []protocol.PeerObservation{{DeviceID: "gateway-1"}, {DeviceID: "foreign"}}

	if err := service.Report(
		t.Context(),
		gateway,
		report,
	); !errors.Is(
		err,
		telemetry.ErrUnauthorized,
	) {
		t.Fatalf("unsigned gateway peer accepted: %v", err)
	}

	rows, err = repository.Latest(t.Context(), 200)

	if err != nil || len(rows) != 0 {
		t.Fatalf("partial gateway write: %+v %v", rows, err)
	}
}
