package devices

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }
func (s *PostgresStore) SaveEnrollmentToken(ctx context.Context, token EnrollmentToken) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO enrollment_tokens(token_hash,role,expires_at) VALUES($1,$2,$3)`, token.Hash[:], token.Role, token.ExpiresAt)
	return err
}

func (s *PostgresStore) ConsumeEnrollmentToken(ctx context.Context, hash [32]byte, now time.Time) (Role, error) {
	var role Role
	err := s.pool.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2 RETURNING role`, hash[:], now).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidEnrollmentToken
	}
	return role, err
}

func (s *PostgresStore) SaveDevice(ctx context.Context, d Device) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, d.ID, d.Name, d.Role, d.Status, d.IdentityPublicKey, d.WireGuardPublicKey, d.CreatedAt); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`, d.ID, d.CredentialHash[:], d.CreatedAt.Add(CredentialTTL)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) Enroll(ctx context.Context, hash [32]byte, now time.Time, d Device) (Role, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var role Role
	if err = tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2 RETURNING role`, hash[:], now).Scan(&role); errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidEnrollmentToken
	} else if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, d.ID, d.Name, role, d.Status, d.IdentityPublicKey, d.WireGuardPublicKey, d.CreatedAt); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`, d.ID, d.CredentialHash[:], d.CreatedAt.Add(CredentialTTL)); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return role, nil
}

func (s *PostgresStore) Device(ctx context.Context, id string) (Device, error) {
	var d Device
	err := s.pool.QueryRow(ctx, `SELECT id,name,role,status,identity_public_key,wireguard_public_key,created_at,revoked_at FROM devices WHERE id=$1`, id).Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	return d, err
}

func (s *PostgresStore) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,role,status,identity_public_key,wireguard_public_key,created_at,revoked_at FROM devices ORDER BY created_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeDevice(ctx context.Context, id string, at time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE devices SET status='revoked',revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrDeviceNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE device_credentials SET revoked_at=COALESCE(revoked_at,$2) WHERE device_id=$1`, id, at); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) AuthenticateCredential(ctx context.Context, hash [32]byte, now time.Time) (Device, error) {
	var d Device
	err := s.pool.QueryRow(ctx, `SELECT d.id,d.name,d.role,d.status,d.identity_public_key,d.wireguard_public_key,d.created_at,d.revoked_at FROM device_credentials c JOIN devices d ON d.id=c.device_id WHERE c.credential_hash=$1 AND c.revoked_at IS NULL AND c.expires_at>$2 AND d.status='active'`, hash[:], now).Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, ErrDeviceNotFound
	}
	return d, err
}

func (s *PostgresStore) RotateCredential(ctx context.Context, id string, oldHash, newHash [32]byte, now, expiresAt time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var deviceID string
	err = tx.QueryRow(ctx, `UPDATE device_credentials c SET revoked_at=$3 WHERE c.device_id=$1 AND c.credential_hash=$2 AND c.revoked_at IS NULL AND c.expires_at>$3 AND EXISTS (SELECT 1 FROM devices d WHERE d.id=c.device_id AND d.status='active') RETURNING c.device_id`, id, oldHash[:], now).Scan(&deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDeviceNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`, deviceID, newHash[:], expiresAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
