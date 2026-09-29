package invites

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists pending proofs so a control restart cannot silently
// forget an in-progress onboarding flow. The short code is intentionally not
// a column: it exists only in the trusted companion process.
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) Save(ctx context.Context, record Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO invite_records(
			invite_id, profile_id, device_id, device_public_key,
			permit_version, permit_key_id, permit_payload, permit_signature,
			proof_version, proof_device_public_key, proof_code_digest, proof_signature, proof_device_signature,
			status, created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		record.InviteID, record.ProfileID, record.DeviceID, record.DevicePublic,
		record.Permit.Version, record.Permit.KeyID, record.Permit.Payload, record.Permit.Signature,
		record.Proof.Version, record.Proof.DevicePublicKey, record.Proof.CodeDigest, record.Proof.Signature, record.Proof.DeviceSignature,
		record.Status, record.CreatedAt)
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Record, error) {
	var record Record
	var permitVersion, proofVersion int
	err := s.pool.QueryRow(ctx, `
		SELECT invite_id, profile_id, device_id, device_public_key,
		       permit_version, permit_key_id, permit_payload, permit_signature,
		       proof_version, proof_device_public_key, proof_code_digest, proof_signature, proof_device_signature,
		       status, created_at, approved_at
		FROM invite_records WHERE invite_id=$1`, id).Scan(
		&record.InviteID, &record.ProfileID, &record.DeviceID, &record.DevicePublic,
		&permitVersion, &record.Permit.KeyID, &record.Permit.Payload, &record.Permit.Signature,
		&proofVersion, &record.Proof.DevicePublicKey, &record.Proof.CodeDigest, &record.Proof.Signature, &record.Proof.DeviceSignature,
		&record.Status, &record.CreatedAt, &record.ApprovedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrInviteNotFound
	}
	if err != nil {
		return Record{}, err
	}
	record.Permit.Version = uint16(permitVersion)
	record.Proof.Version = uint16(proofVersion)
	record.Permit.Signature = append([]byte(nil), record.Permit.Signature...)
	record.Proof.InviteID = record.InviteID
	record.Proof.DeviceID = record.DeviceID
	record.Permit.Payload = append([]byte(nil), record.Permit.Payload...)
	record.DevicePublic = append([]byte(nil), record.DevicePublic...)
	return record, nil
}

func (s *PostgresStore) Approve(ctx context.Context, id string, at time.Time) (Record, error) {
	var record Record
	err := s.pool.QueryRow(ctx, `
		UPDATE invite_records SET status='approved', approved_at=$2
		WHERE invite_id=$1 AND status='pending'
		RETURNING invite_id`, id, at).Scan(&record.InviteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrInviteConsumed
	}
	if err != nil {
		return Record{}, err
	}
	return s.Get(ctx, record.InviteID)
}

var _ Store = (*PostgresStore)(nil)
