package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/invites"
)

// Repository persists pending proofs so a control restart cannot silently
// forget an in-progress onboarding flow. The short code is intentionally not
// a column: it exists only in the trusted companion process.
type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type Repository struct{ db DB }

func Bind(tx pgx.Tx) *Repository { return &Repository{db: tx} }

func New(pool *pgxpool.Pool) *Repository { return &Repository{db: pool} }

func (s *Repository) Save(ctx context.Context, record invites.Record) error {
	tag, err := s.db.Exec(
		ctx,
		`
		INSERT INTO invite_records(
			invite_id, profile_id, device_id, device_public_key, wireguard_public_key,
			permit_version, permit_key_id, permit_payload, permit_signature,
			proof_version, proof_device_public_key, proof_code_digest, proof_signature, proof_device_signature,
			status, created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) ON CONFLICT(invite_id) DO NOTHING`,
		record.InviteID,
		record.ProfileID,
		record.DeviceID,
		record.DevicePublic,
		record.WireGuardPublicKey,
		record.Permit.Version,
		record.Permit.KeyID,
		record.Permit.Payload,
		record.Permit.Signature,
		record.Proof.Version,
		record.Proof.DevicePublicKey,
		record.Proof.CodeDigest,
		record.Proof.Signature,
		record.Proof.DeviceSignature,
		record.Status,
		record.CreatedAt,
	)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		current, err := s.Get(ctx, record.InviteID)
		if err != nil {
			return err
		}
		if current.Status == invites.StatusBlocked {
			return invites.ErrInviteBlocked
		}
		if !invites.SameSubmission(current, record) {
			return invites.ErrInviteConsumed
		}
	}

	return nil
}

func (s *Repository) Get(ctx context.Context, id string) (invites.Record, error) {
	var record invites.Record
	var permitVersion, proofVersion int

	err := s.db.QueryRow(ctx, `
		SELECT invite_id, profile_id, device_id, device_public_key, wireguard_public_key,
		       permit_version, permit_key_id, permit_payload, permit_signature,
		       proof_version, proof_device_public_key, proof_code_digest, proof_signature, proof_device_signature,
		       status, created_at, approved_at, failed_code_attempts, blocked_at
		FROM invite_records WHERE invite_id=$1`, id).Scan(
		&record.InviteID, &record.ProfileID, &record.DeviceID, &record.DevicePublic, &record.WireGuardPublicKey,
		&permitVersion, &record.Permit.KeyID, &record.Permit.Payload, &record.Permit.Signature,
		&proofVersion, &record.Proof.DevicePublicKey, &record.Proof.CodeDigest, &record.Proof.Signature, &record.Proof.DeviceSignature,
		&record.Status, &record.CreatedAt, &record.ApprovedAt, &record.FailedCodeAttempts, &record.BlockedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Record{}, invites.ErrInviteNotFound
	}
	if err != nil {
		return invites.Record{}, err
	}

	record.Permit.Version = uint16(permitVersion)
	record.Proof.Version = uint16(proofVersion)
	record.Permit.Signature = append([]byte(nil), record.Permit.Signature...)
	record.Proof.InviteID = record.InviteID
	record.Proof.DeviceID = record.DeviceID
	record.Proof.WireGuardPublicKey = append([]byte(nil), record.WireGuardPublicKey...)
	record.Permit.Payload = append([]byte(nil), record.Permit.Payload...)
	record.DevicePublic = append([]byte(nil), record.DevicePublic...)

	return record, nil
}

func (s *Repository) Approve(ctx context.Context, id string, at time.Time) (invites.Record, error) {
	var record invites.Record

	err := s.db.QueryRow(ctx, `
		UPDATE invite_records SET status='approved', approved_at=$2
		WHERE invite_id=$1 AND status='pending'
		RETURNING invite_id`, id, at).Scan(&record.InviteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Record{}, invites.ErrInviteConsumed
	}
	if err != nil {
		return invites.Record{}, err
	}

	return s.Get(ctx, record.InviteID)
}

// RecordInvalidCodeAttempt updates the lockout state in one SQL statement.
// The predicate excludes approved/blocked records and the returned status
// makes the fifth failure durable even when several companion workers race.
func (s *Repository) RecordInvalidCodeAttempt(ctx context.Context, id string, at time.Time) error {
	var status invites.Status

	err := s.db.QueryRow(ctx, `
		UPDATE invite_records
		SET failed_code_attempts = failed_code_attempts + 1,
		    status = CASE WHEN failed_code_attempts + 1 >= $2 THEN 'blocked' ELSE status END,
		    blocked_at = CASE WHEN failed_code_attempts + 1 >= $2 THEN $3 ELSE blocked_at END
		WHERE invite_id=$1 AND status='pending' AND failed_code_attempts < $2
		RETURNING status`, id, invites.MaxInvalidCodeAttempts, at).Scan(&status)
	if err == nil {
		if status == invites.StatusBlocked {
			return invites.ErrInviteBlocked
		}

		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	record, getErr := s.Get(ctx, id)
	if getErr != nil {
		return getErr
	}
	if record.Status == invites.StatusBlocked {
		return invites.ErrInviteBlocked
	}

	return invites.ErrInviteConsumed
}

var _ invites.Repository = (*Repository)(nil)

func (s *Repository) Lock(ctx context.Context, id string) (invites.Record, error) {
	var locked string

	err := s.db.QueryRow(ctx, `SELECT invite_id FROM invite_records WHERE invite_id=$1 FOR UPDATE`, id).
		Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return invites.Record{}, invites.ErrInviteNotFound
	}
	if err != nil {
		return invites.Record{}, err
	}

	return s.Get(ctx, id)
}
