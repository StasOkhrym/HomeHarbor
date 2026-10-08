package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (s *Repository) CreateProfile(ctx context.Context, profile profiles.AccessProfile) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO access_profiles(id,name,created_at) VALUES($1,$2,$3)`,
		profile.ID,
		profile.Name,
		profile.CreatedAt,
	); isUniqueViolation(
		err,
	) {
		return profiles.ErrDuplicateID
	} else if err != nil {
		return err
	}

	for _, serviceID := range profile.ServiceIDs {
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO access_profile_services(profile_id,service_id) VALUES($1,$2)`,
			profile.ID,
			serviceID,
		); err != nil {
			return err
		}
	}

	for _, deviceID := range profile.DeviceIDs {
		var tag pgconn.CommandTag

		tag, err = tx.Exec(
			ctx,
			`INSERT INTO access_profile_devices(profile_id,device_id)
			 SELECT $1,d.id FROM devices d
			 WHERE d.id=$2 AND d.status='active' FOR SHARE`,
			profile.ID,
			deviceID,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return profiles.ErrDeviceNotAllowed
		}
	}

	return tx.Commit(ctx)
}

func (s *Repository) ListProfiles(ctx context.Context) ([]profiles.AccessProfile, error) {
	rows, err := s.pool.Query(
		ctx,
		`SELECT p.id,p.name,p.created_at,COALESCE(array_agg(DISTINCT ps.service_id) FILTER (WHERE ps.service_id IS NOT NULL),'{}'),COALESCE(array_agg(DISTINCT pd.device_id) FILTER (WHERE pd.device_id IS NOT NULL),'{}') FROM access_profiles p LEFT JOIN access_profile_services ps ON ps.profile_id=p.id LEFT JOIN access_profile_devices pd ON pd.profile_id=p.id GROUP BY p.id ORDER BY p.id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []profiles.AccessProfile{}
	for rows.Next() {
		var item profiles.AccessProfile

		if err = rows.Scan(
			&item.ID,
			&item.Name,
			&item.CreatedAt,
			&item.ServiceIDs,
			&item.DeviceIDs,
		); err != nil {
			return nil, err
		}

		items = append(items, item)
	}

	return items, rows.Err()
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var _ profiles.Repository = (*Repository)(nil)
