package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

func (s *Repository) UpdateMetadata(ctx context.Context, id string, value devices.Metadata) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	tag, err := tx.Exec(
		ctx,
		`UPDATE devices SET name=$2 WHERE id=$1 AND status='active'`,
		id,
		value.Name,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return devices.ErrDeviceNotFound
	}

	_, err = tx.Exec(
		ctx,
		`INSERT INTO device_metadata(device_id,platform,os_version,client_version,reported_at) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(device_id) DO UPDATE SET platform=EXCLUDED.platform,os_version=EXCLUDED.os_version,client_version=EXCLUDED.client_version,reported_at=EXCLUDED.reported_at`,
		id,
		value.Platform,
		value.OSVersion,
		value.ClientVersion,
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// PublicMetadata is read through the owning adapter in the mutation transaction.
// No caller has to know devices' storage schema or fetch credential material.
func (s *Transaction) PublicMetadata(
	ctx context.Context,
	id string,
) (devices.Metadata, devices.Role, error) {
	var value devices.Metadata
	var role devices.Role

	err := s.tx.QueryRow(ctx, `SELECT d.name,d.role,COALESCE(m.platform,''),COALESCE(m.os_version,''),COALESCE(m.client_version,'')
 FROM devices d LEFT JOIN device_metadata m ON m.device_id=d.id WHERE d.id=$1`, id).
		Scan(&value.Name, &role, &value.Platform, &value.OSVersion, &value.ClientVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return devices.Metadata{}, "", devices.ErrDeviceNotFound
	}

	return value, role, err
}
