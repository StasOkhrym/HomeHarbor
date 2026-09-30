package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/services"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (s *Repository) CreateService(ctx context.Context, item services.Service) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO services(id,name,kind,url,native_url,health_url,description,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, item.ID, item.Name, item.Kind, item.URL, nullableString(item.NativeURL), nullableString(item.HealthURL), item.Description, item.CreatedAt)
	if isUniqueViolation(err) {
		return services.ErrDuplicateID
	}
	return err
}

func (s *Repository) ListServices(ctx context.Context) ([]services.Service, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,kind,url,COALESCE(native_url,''),COALESCE(health_url,''),description,created_at FROM services ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []services.Service{}
	for rows.Next() {
		var item services.Service
		if err = rows.Scan(&item.ID, &item.Name, &item.Kind, &item.URL, &item.NativeURL, &item.HealthURL, &item.Description, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Repository) ListServicesForDevice(ctx context.Context, deviceID string) ([]services.Service, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT s.id,s.name,s.kind,s.url,COALESCE(s.native_url,''),
		       COALESCE(s.health_url,''),s.description,s.created_at
		FROM services s
		JOIN access_profile_services aps ON aps.service_id=s.id
		JOIN access_profile_devices apd ON apd.profile_id=aps.profile_id
		WHERE apd.device_id=$1
		ORDER BY s.id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []services.Service{}
	for rows.Next() {
		var item services.Service
		if err = rows.Scan(&item.ID, &item.Name, &item.Kind, &item.URL, &item.NativeURL, &item.HealthURL, &item.Description, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Repository) CreateProfile(ctx context.Context, profile services.AccessProfile) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `INSERT INTO access_profiles(id,name,created_at) VALUES($1,$2,$3)`, profile.ID, profile.Name, profile.CreatedAt); isUniqueViolation(err) {
		return services.ErrDuplicateID
	} else if err != nil {
		return err
	}
	for _, serviceID := range profile.ServiceIDs {
		if _, err = tx.Exec(ctx, `INSERT INTO access_profile_services(profile_id,service_id) VALUES($1,$2)`, profile.ID, serviceID); err != nil {
			return err
		}
	}
	for _, deviceID := range profile.DeviceIDs {
		if _, err = tx.Exec(ctx, `INSERT INTO access_profile_devices(profile_id,device_id) VALUES($1,$2)`, profile.ID, deviceID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Repository) ListProfiles(ctx context.Context) ([]services.AccessProfile, error) {
	rows, err := s.pool.Query(ctx, `SELECT p.id,p.name,p.created_at,COALESCE(array_agg(DISTINCT ps.service_id) FILTER (WHERE ps.service_id IS NOT NULL),'{}'),COALESCE(array_agg(DISTINCT pd.device_id) FILTER (WHERE pd.device_id IS NOT NULL),'{}') FROM access_profiles p LEFT JOIN access_profile_services ps ON ps.profile_id=p.id LEFT JOIN access_profile_devices pd ON pd.profile_id=p.id GROUP BY p.id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []services.AccessProfile{}
	for rows.Next() {
		var item services.AccessProfile
		if err = rows.Scan(&item.ID, &item.Name, &item.CreatedAt, &item.ServiceIDs, &item.DeviceIDs); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func nullableString(value string) *string {
	if value == "" {
		return nil
	}

	return &value
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

var _ services.Repository = (*Repository)(nil)
