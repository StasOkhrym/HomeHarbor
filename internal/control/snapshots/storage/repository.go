package storage

import (
	"bytes"
	"context"
	"errors"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/snapshots"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// Append locks even an empty network before reading its head. Row locks alone
// cannot serialize genesis; READ COMMITTED sees the winner after lock wait.
func (s *Repository) Append(ctx context.Context, networkID string, expectedRevision uint64, expectedHash []byte, envelope snapshot.Envelope) error {
	value, err := snapshot.Decode(envelope)
	if err != nil {
		return err
	}
	if value.NetworkID != networkID || expectedRevision >= math.MaxInt64 || value.Revision != expectedRevision+1 {
		return snapshot.ErrRevisionGap
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "go_tunnels_snapshots/"+networkID); err != nil {
		return err
	}
	var revision uint64
	var hash []byte
	err = tx.QueryRow(ctx, `SELECT revision,hash FROM network_snapshots WHERE network_id=$1 ORDER BY revision DESC LIMIT 1`, networkID).Scan(&revision, &hash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if revision != expectedRevision || !bytes.Equal(hash, expectedHash) {
		return snapshots.ErrSnapshotConflict
	}
	if !bytes.Equal(value.PreviousHash, hash) {
		return snapshot.ErrPreviousHash
	}
	_, err = tx.Exec(ctx, `INSERT INTO network_snapshots(network_id,revision,envelope_version,key_id,payload,hash,signature,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,now())`, networkID, value.Revision, envelope.Version, envelope.KeyID, envelope.Payload, envelope.Hash, envelope.Signature)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return snapshots.ErrSnapshotConflict
		}
		return err
	}
	return tx.Commit(ctx)
}

func (s *Repository) Latest(ctx context.Context, networkID string) (snapshot.Envelope, error) {
	var envelope snapshot.Envelope
	var version int
	err := s.pool.QueryRow(ctx, `SELECT envelope_version,key_id,payload,hash,signature FROM network_snapshots WHERE network_id=$1 ORDER BY revision DESC LIMIT 1`, networkID).Scan(&version, &envelope.KeyID, &envelope.Payload, &envelope.Hash, &envelope.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot.Envelope{}, snapshots.ErrSnapshotUnavailable
	}
	if err != nil {
		return snapshot.Envelope{}, err
	}
	envelope.Version = uint16(version)
	return envelope, nil
}

func (s *Repository) History(ctx context.Context, networkID string, afterRevision uint64, limit int) ([]snapshot.Envelope, error) {
	if limit < 1 || limit > snapshots.MaxHistoryPageSize+1 || afterRevision > math.MaxInt64 {
		return nil, snapshots.ErrHistoryCursor
	}
	rows, err := s.pool.Query(ctx, `SELECT envelope_version,key_id,payload,hash,signature FROM network_snapshots WHERE network_id=$1 AND revision>$2 ORDER BY revision LIMIT $3`, networkID, afterRevision, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []snapshot.Envelope{}
	for rows.Next() {
		var envelope snapshot.Envelope
		var version int
		if err := rows.Scan(&version, &envelope.KeyID, &envelope.Payload, &envelope.Hash, &envelope.Signature); err != nil {
			return nil, err
		}
		envelope.Version = uint16(version)
		result = append(result, envelope)
	}
	return result, rows.Err()
}

var _ snapshots.Repository = (*Repository)(nil)
