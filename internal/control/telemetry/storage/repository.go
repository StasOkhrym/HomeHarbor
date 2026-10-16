package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/telemetry"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (r *Repository) Begin(ctx context.Context, deviceID string, now time.Time) (uint64, error) {
	var generation uint64

	err := r.pool.QueryRow(ctx, `INSERT INTO telemetry_reporters(device_id,generation,started_at) VALUES($1,1,$2)
 ON CONFLICT(device_id) DO UPDATE SET generation=telemetry_reporters.generation+1,last_sequence=0,started_at=EXCLUDED.started_at
 RETURNING generation`, deviceID, now).
		Scan(&generation)

	return generation, err
}

func (r *Repository) Record(
	ctx context.Context,
	deviceID string,
	role devices.Role,
	report protocol.TelemetryReport,
	now time.Time,
) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	// This row lock serializes admission and reports across independent control
	// replicas. A stale writer can never advance a newer connection generation.
	tag, err := tx.Exec(ctx, `UPDATE telemetry_reporters SET last_sequence=$3,observed_at=$4
 WHERE device_id=$1 AND generation=$2 AND last_sequence<$3`, deviceID, report.Generation, report.Sequence, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return telemetry.ErrStaleReport
	}

	if _, err := tx.Exec(
		ctx,
		`DELETE FROM telemetry_observations WHERE reporter_device_id=$1`,
		deviceID,
	); err != nil {
		return err
	}

	for _, sample := range report.Observations {
		data, err := json.Marshal(sample)
		if err != nil {
			return err
		}

		_, err = tx.Exec(
			ctx,
			`INSERT INTO telemetry_observations(reporter_device_id,subject_device_id,reporter_role,generation,report_sequence,runtime_id,runtime_state,applied_revision,observed_at,sample)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			deviceID,
			sample.DeviceID,
			role,
			report.Generation,
			report.Sequence,
			report.RuntimeID,
			report.State,
			report.AppliedRevision,
			now,
			data,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *Repository) Latest(ctx context.Context, limit int) ([]telemetry.Observation, error) {
	if limit < 1 {
		limit = 200
	}

	if limit > 1000 {
		limit = 1000
	}

	rows, err := r.pool.Query(
		ctx,
		`SELECT reporter_device_id,subject_device_id,reporter_role,generation,report_sequence,runtime_id::text,runtime_state,applied_revision,observed_at,sample
 FROM telemetry_observations ORDER BY observed_at DESC,reporter_device_id,subject_device_id LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []telemetry.Observation{}
	for rows.Next() {
		var observation telemetry.Observation
		var data []byte

		if err := rows.Scan(
			&observation.ReporterDeviceID,
			&observation.SubjectDeviceID,
			&observation.ReporterRole,
			&observation.Generation,
			&observation.Sequence,
			&observation.RuntimeID,
			&observation.State,
			&observation.AppliedRevision,
			&observation.ObservedAt,
			&data,
		); err != nil {
			return nil, err
		}

		if err := json.Unmarshal(data, &observation.Sample); err != nil {
			return nil, err
		}

		result = append(result, observation)
	}

	return result, rows.Err()
}

var _ telemetry.Repository = (*Repository)(nil)
