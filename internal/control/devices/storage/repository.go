package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

type DB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Begin(context.Context) (pgx.Tx, error)
}
type (
	EventAppender func(context.Context, pgx.Tx, devices.Event) error
	Repository    struct {
		db     DB
		append EventAppender
	}
	Transaction struct{ tx pgx.Tx }
)

func Bind(tx pgx.Tx) *Transaction { return &Transaction{tx: tx} }

// New requires an explicit transactional publication port for mutations.
// Omitting it fails closed rather than falling back to a domain publisher.
func New(pool *pgxpool.Pool, appender ...EventAppender) *Repository {
	var append EventAppender
	if len(appender) > 0 {
		append = appender[0]
	}

	return &Repository{db: pool, append: append}
}

func (s *Repository) SaveEnrollmentToken(ctx context.Context, token devices.EnrollmentToken) error {
	_, err := s.db.Exec(
		ctx,
		`INSERT INTO enrollment_tokens(token_hash,role,expires_at) VALUES($1,$2,$3)`,
		token.Hash[:],
		token.Role,
		token.ExpiresAt,
	)
	return err
}

func (s *Repository) ConsumeEnrollmentToken(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (devices.Role, error) {
	var role devices.Role
	err := s.db.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2 RETURNING role`, hash[:], now).
		Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", devices.ErrInvalidEnrollmentToken
	}
	return role, err
}

func (s *Repository) SaveDevice(ctx context.Context, d devices.Device) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		d.ID,
		d.Name,
		d.Role,
		d.Status,
		d.IdentityPublicKey,
		d.WireGuardPublicKey,
		d.CreatedAt,
	); err != nil {
		return err
	}
	if _, err = tx.Exec(
		ctx,
		`INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`,
		d.ID,
		d.CredentialHash[:],
		d.CredentialExpiration(),
	); err != nil {
		return err
	}
	if err = s.appendEvent(
		ctx,
		tx,
		devices.Event{Type: "device.enrolled", AggregateID: d.ID, OccurredAt: d.CreatedAt},
	); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Repository) Enroll(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
	d devices.Device,
) (devices.Role, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var role devices.Role

	if err = tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=$2 WHERE token_hash=$1 AND used_at IS NULL AND expires_at>$2 RETURNING role`, hash[:], now).
		Scan(&role); errors.Is(
		err,
		pgx.ErrNoRows,
	) {
		return "", devices.ErrInvalidEnrollmentToken
	} else if err != nil {
		return "", err
	}

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		d.ID,
		d.Name,
		role,
		d.Status,
		d.IdentityPublicKey,
		d.WireGuardPublicKey,
		d.CreatedAt,
	); err != nil {
		return "", err
	}

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`,
		d.ID,
		d.CredentialHash[:],
		d.CredentialExpiration(),
	); err != nil {
		return "", err
	}

	// The enrollment transaction owns both the one-time token and the device.
	// Recording the outbox event before commit prevents a successful enrollment
	// from becoming invisible to audit consumers after a control restart.
	if err = s.appendEvent(
		ctx,
		tx,
		devices.Event{Type: "device.enrolled", AggregateID: d.ID, OccurredAt: d.CreatedAt},
	); err != nil {
		return "", err
	}

	if err = tx.Commit(ctx); err != nil {
		return "", err
	}

	return role, nil
}

func (s *Repository) Device(ctx context.Context, id string) (devices.Device, error) {
	var d devices.Device

	err := s.db.QueryRow(ctx, `SELECT id,name,role,status,identity_public_key,wireguard_public_key,created_at,revoked_at FROM devices WHERE id=$1`, id).
		Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.Device{}, devices.ErrDeviceNotFound
	}

	return d, err
}

func (s *Repository) ListDevices(ctx context.Context) ([]devices.Device, error) {
	rows, err := s.db.Query(
		ctx,
		`SELECT id,name,role,status,identity_public_key,wireguard_public_key,created_at,revoked_at FROM devices ORDER BY created_at,id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []devices.Device{}
	for rows.Next() {
		var d devices.Device

		if err := rows.Scan(
			&d.ID,
			&d.Name,
			&d.Role,
			&d.Status,
			&d.IdentityPublicKey,
			&d.WireGuardPublicKey,
			&d.CreatedAt,
			&d.RevokedAt,
		); err != nil {
			return nil, err
		}

		out = append(out, d)
	}

	return out, rows.Err()
}

func (s *Repository) RevokeDevice(ctx context.Context, id string, at time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(
		ctx,
		`UPDATE devices SET status='revoked',revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`,
		id,
		at,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return devices.ErrDeviceNotFound
	}

	if _, err = tx.Exec(
		ctx,
		`UPDATE device_credentials SET revoked_at=COALESCE(revoked_at,$2) WHERE device_id=$1`,
		id,
		at,
	); err != nil {
		return err
	}

	if err = s.appendEvent(
		ctx,
		tx,
		devices.Event{Type: "device.revoked", AggregateID: id, OccurredAt: at},
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Repository) AuthenticateCredential(
	ctx context.Context,
	hash [32]byte,
	now time.Time,
) (devices.Device, error) {
	var d devices.Device
	err := s.db.QueryRow(ctx, `SELECT d.id,d.name,d.role,d.status,d.identity_public_key,d.wireguard_public_key,d.created_at,d.revoked_at FROM device_credentials c JOIN devices d ON d.id=c.device_id WHERE c.credential_hash=$1 AND c.revoked_at IS NULL AND c.expires_at>$2 AND d.status='active'`, hash[:], now).
		Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.Device{}, devices.ErrDeviceNotFound
	}
	return d, err
}

func (s *Repository) RotateCredential(
	ctx context.Context,
	id string,
	oldHash, newHash [32]byte,
	now, expiresAt time.Time,
) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var deviceID string

	// Claim and revoke own the device row before touching credentials. Rotation
	// must use the same order: INSERT's device FK can otherwise wait on a claim
	// while holding the credential row that the claim needs, forming a deadlock.
	err = tx.QueryRow(ctx, `SELECT id FROM devices WHERE id=$1 AND status='active' FOR UPDATE`, id).
		Scan(&deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.ErrDeviceNotFound
	}
	if err != nil {
		return err
	}

	err = tx.QueryRow(ctx, `UPDATE device_credentials c SET revoked_at=$3 WHERE c.device_id=$1 AND c.credential_hash=$2 AND c.revoked_at IS NULL AND c.expires_at>$3 AND EXISTS (SELECT 1 FROM devices d WHERE d.id=c.device_id AND d.status='active') RETURNING c.device_id`, id, oldHash[:], now).
		Scan(&deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.ErrDeviceNotFound
	}
	if err != nil {
		return err
	}

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`,
		deviceID,
		newHash[:],
		expiresAt,
	); err != nil {
		return err
	}

	if err = s.appendEvent(
		ctx,
		tx,
		devices.Event{Type: "device.credential_rotated", AggregateID: deviceID, OccurredAt: now},
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Repository) appendEvent(ctx context.Context, tx pgx.Tx, event devices.Event) error {
	if s.append == nil {
		return errors.New("transactional event appender is required")
	}

	return s.append(ctx, tx, event)
}

var (
	_ devices.Repository     = (*Repository)(nil)
	_ devices.EnrollmentPort = (*Repository)(nil)
)
