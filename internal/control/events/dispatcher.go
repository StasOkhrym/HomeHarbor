package events

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
)

type AuditProjector interface {
	WriteTx(context.Context, pgx.Tx, audit.Event) error
}

type Dispatcher struct {
	pool      *pgxpool.Pool
	projector AuditProjector
	logger    *slog.Logger
	running   atomic.Bool
}

func NewDispatcher(pool *pgxpool.Pool, projector AuditProjector, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}

	return &Dispatcher{pool: pool, projector: projector, logger: logger}
}

func (d *Dispatcher) Run(ctx context.Context) error {
	if d.pool == nil || d.projector == nil {
		return errors.New("audit dispatcher dependencies are required")
	}

	d.running.Store(true)
	defer d.running.Store(false)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		if err := d.DispatchBatch(ctx); err != nil && ctx.Err() == nil {
			d.logger.Error(
				"audit delivery retry scheduled",
				"error",
				"audit projection unavailable",
			)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// DispatchBatch projects up to 50 rows, each with its completion marker in
// the same SQL transaction and on the same acquired connection.
func (d *Dispatcher) DispatchBatch(ctx context.Context) error {
	if d.pool == nil || d.projector == nil {
		return errors.New("audit dispatcher dependencies are required")
	}

	for range 50 {
		found, err := d.dispatchOne(ctx)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
	}

	return nil
}

func (d *Dispatcher) dispatchOne(ctx context.Context) (bool, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer rollbackBounded(tx, 2*time.Second)

	var id int64
	var topic string
	var payload []byte
	var attempts int

	err = tx.QueryRow(ctx, `SELECT id,topic,payload,attempts FROM event_outbox
 WHERE published_at IS NULL AND quarantined_at IS NULL
 AND (next_attempt_at IS NULL OR next_attempt_at <= now())
 ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &topic, &payload, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	fact, err := Decode(id, payload)
	if err == nil && fact.Type != topic {
		err = errors.New("event topic mismatch")
	}

	if err != nil {
		_, err = tx.Exec(ctx, `UPDATE event_outbox SET attempts=attempts+1,
   last_error='invalid event envelope',quarantined_at=now(),next_attempt_at=NULL WHERE id=$1`, id)
		if err == nil {
			err = tx.Commit(ctx)
		}

		if err == nil {
			return true, nil
		}

		return true, d.persistFailure(ctx, tx, id, attempts, "audit quarantine failed")
	}

	if err = d.projector.WriteTx(ctx, tx, fact.AuditEvent()); err == nil {
		_, err = tx.Exec(ctx, `UPDATE event_outbox SET published_at=now(),attempts=attempts+1,
   last_error=NULL,next_attempt_at=NULL WHERE id=$1`, id)
	}

	if err == nil {
		err = tx.Commit(ctx)
		if err == nil {
			return true, nil
		}
	}

	return true, d.persistFailure(ctx, tx, id, attempts, "audit projection failed")
}

// persistFailure runs outside the failed delivery transaction. A conditional
// update avoids marking a row failed if its commit succeeded but the reply was
// lost, or another dispatcher already completed it.
func (d *Dispatcher) persistFailure(
	ctx context.Context,
	tx pgx.Tx,
	id int64,
	attempts int,
	reason string,
) error {
	rollbackBounded(tx, 2*time.Second)
	retryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()

	_, err := d.pool.Exec(retryCtx, `UPDATE event_outbox SET attempts=attempts+1,
 last_error=$3,next_attempt_at=now()+($2::integer*interval '1 second')
 WHERE id=$1 AND published_at IS NULL AND quarantined_at IS NULL`, id, retrySeconds(attempts), reason)
	if err != nil {
		return errors.New("audit delivery and retry state unavailable")
	}

	return errors.New(reason)
}

func retrySeconds(failures int) int {
	seconds := 1
	for i := 0; i < failures && seconds < 60; i++ {
		seconds *= 2
	}

	if seconds > 60 {
		return 60
	}

	return seconds
}

// Check fails readiness for any critical audit row with failed delivery or
// quarantine. A fresh pending row may still be in the normal dispatch window.
func (d *Dispatcher) Check(ctx context.Context) error {
	if d.pool == nil {
		return errors.New("audit dispatcher unavailable")
	}
	var degraded bool
	err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM event_outbox
  WHERE published_at IS NULL AND (attempts > 0 OR quarantined_at IS NOT NULL))`).Scan(&degraded)
	if err != nil {
		return errors.New("audit delivery state unavailable")
	}
	if degraded {
		return errors.New("audit delivery degraded")
	}
	return nil
}

// Ready combines worker liveness with persisted critical delivery state.
func (d *Dispatcher) Ready(ctx context.Context) error {
	if !d.running.Load() {
		return errors.New("audit dispatcher unavailable")
	}

	return d.Check(ctx)
}

// rollbackBounded releases a failed delivery lock even after the request was
// cancelled, while keeping process shutdown bounded if the backend stalls.
func rollbackBounded(tx interface{ Rollback(context.Context) error }, timeout time.Duration) {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_ = tx.Rollback(cleanupCtx)
}
