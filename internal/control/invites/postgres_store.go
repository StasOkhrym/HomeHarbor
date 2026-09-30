package invites

import (
	"context"
	"encoding/json"
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
			invite_id, profile_id, device_id, device_public_key, wireguard_public_key,
			permit_version, permit_key_id, permit_payload, permit_signature,
			proof_version, proof_device_public_key, proof_code_digest, proof_signature, proof_device_signature,
			status, created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		record.InviteID, record.ProfileID, record.DeviceID, record.DevicePublic, record.WireGuardPublicKey,
		record.Permit.Version, record.Permit.KeyID, record.Permit.Payload, record.Permit.Signature,
		record.Proof.Version, record.Proof.DevicePublicKey, record.Proof.CodeDigest, record.Proof.Signature, record.Proof.DeviceSignature,
		record.Status, record.CreatedAt)
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Record, error) {
	var record Record
	var permitVersion, proofVersion int
	err := s.pool.QueryRow(ctx, `
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
	record.Proof.WireGuardPublicKey = append([]byte(nil), record.WireGuardPublicKey...)
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

// RecordInvalidCodeAttempt updates the lockout state in one SQL statement.
// The predicate excludes approved/blocked records and the returned status
// makes the fifth failure durable even when several companion workers race.
func (s *PostgresStore) RecordInvalidCodeAttempt(ctx context.Context, id string, at time.Time) error {
	var status Status
	err := s.pool.QueryRow(ctx, `
		UPDATE invite_records
		SET failed_code_attempts = failed_code_attempts + 1,
		    status = CASE WHEN failed_code_attempts + 1 >= $2 THEN 'blocked' ELSE status END,
		    blocked_at = CASE WHEN failed_code_attempts + 1 >= $2 THEN $3 ELSE blocked_at END
		WHERE invite_id=$1 AND status='pending' AND failed_code_attempts < $2
		RETURNING status`, id, MaxInvalidCodeAttempts, at).Scan(&status)
	if err == nil {
		if status == StatusBlocked {
			return ErrInviteBlocked
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
	if record.Status == StatusBlocked {
		return ErrInviteBlocked
	}
	return ErrInviteConsumed
}

var (
	_ Store     = (*PostgresStore)(nil)
	_ Activator = (*PostgresStore)(nil)
)

func (s *PostgresStore) Activate(ctx context.Context, record Record, device DeviceActivation, at time.Time) (Record, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// All four writes share one transaction. If the profile disappeared, the
	// device key collided, or outbox insertion fails, the invite stays pending
	// and the client can retry after the underlying problem is fixed.
	var inviteID string
	if err = tx.QueryRow(ctx, `UPDATE invite_records SET status='approved', approved_at=$2 WHERE invite_id=$1 AND status='pending' RETURNING invite_id`, record.InviteID, at).Scan(&inviteID); errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrInviteConsumed
	} else if err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,'client','active',$3,$4,$5)`, device.ID, device.Name, device.IdentityPublicKey, device.WireGuardPublicKey, device.CreatedAt); err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`, device.ID, device.CredentialHash[:], device.CreatedAt.Add(15*time.Minute)); err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO access_profile_devices(profile_id,device_id) VALUES($1,$2)`, record.ProfileID, device.ID); err != nil {
		return Record{}, err
	}
	if err = appendEvent(ctx, tx, "device.enrolled", device.ID, device.CreatedAt); err != nil {
		return Record{}, err
	}
	if err = appendEvent(ctx, tx, "invite.approved", record.InviteID, at); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, err
	}
	return s.Get(ctx, inviteID)
}

func appendEvent(ctx context.Context, tx pgx.Tx, topic, aggregateID string, occurredAt time.Time) error {
	payload, err := json.Marshal(map[string]any{"type": topic, "aggregate_id": aggregateID, "occurred_at": occurredAt})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO event_outbox(topic,payload,occurred_at) VALUES($1,$2,$3)`, topic, payload, occurredAt)
	return err
}
