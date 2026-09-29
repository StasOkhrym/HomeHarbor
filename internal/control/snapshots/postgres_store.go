package snapshots

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) Save(ctx context.Context, envelope snapshot.Envelope) error {
	value, err := snapshot.Decode(envelope)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO network_snapshots(network_id,revision,envelope_version,key_id,payload,hash,signature,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,now())`, value.NetworkID, value.Revision, envelope.Version, envelope.KeyID, envelope.Payload, envelope.Hash, envelope.Signature)
	return err
}

func (s *PostgresStore) Latest(ctx context.Context) (snapshot.Envelope, error) {
	var envelope snapshot.Envelope
	var version int
	err := s.pool.QueryRow(ctx, `SELECT envelope_version,key_id,payload,hash,signature FROM network_snapshots ORDER BY revision DESC LIMIT 1`).Scan(&version, &envelope.KeyID, &envelope.Payload, &envelope.Hash, &envelope.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return snapshot.Envelope{}, ErrSnapshotUnavailable
	}
	if err != nil {
		return snapshot.Envelope{}, err
	}
	envelope.Version = uint16(version)
	return envelope, nil
}

var _ Store = (*PostgresStore)(nil)
