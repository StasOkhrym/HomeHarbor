package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
)

// CreateIdentity writes device public metadata only. Approval never creates
// a bearer credential; possession is proved by the later claim.
func (s *Transaction) CreateIdentity(ctx context.Context, d devices.Device) error {
	_, err := s.tx.Exec(ctx, `INSERT INTO devices(id,name,role,status,identity_public_key,wireguard_public_key,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, d.ID, d.Name, d.Role, d.Status, d.IdentityPublicKey, d.WireGuardPublicKey, d.CreatedAt)
	return err
}

// ReplaceCredential serializes claim, rotation and revocation on the device
// row. The unique partial index provides a second, durable invariant.
func (s *Transaction) ReplaceCredential(ctx context.Context, id string, hash [32]byte, now, expires time.Time) (devices.Device, error) {
	var d devices.Device
	err := s.tx.QueryRow(ctx, `SELECT id,name,role,status,identity_public_key,wireguard_public_key,created_at,revoked_at FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&d.ID, &d.Name, &d.Role, &d.Status, &d.IdentityPublicKey, &d.WireGuardPublicKey, &d.CreatedAt, &d.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && d.Status != devices.StatusActive {
		return devices.Device{}, devices.ErrDeviceNotFound
	}
	if err != nil {
		return devices.Device{}, err
	}
	if _, err = s.tx.Exec(ctx, `UPDATE device_credentials SET revoked_at=$2 WHERE device_id=$1 AND revoked_at IS NULL`, id, now); err != nil {
		return devices.Device{}, err
	}
	if _, err = s.tx.Exec(ctx, `INSERT INTO device_credentials(device_id,credential_hash,expires_at) VALUES($1,$2,$3)`, id, hash[:], expires); err != nil {
		return devices.Device{}, err
	}
	return d, nil
}
