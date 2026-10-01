package storage

import (
	"context"
	"net/netip"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/routes"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }
func (s *Repository) Save(ctx context.Context, item routes.Advertisement) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO advertised_routes(id,gateway_device_id,prefix,status,created_at) VALUES($1,$2,$3,$4,$5)`,
		item.ID,
		item.GatewayDeviceID,
		item.Prefix.String(),
		item.Status,
		item.CreatedAt,
	); err != nil {
		return err
	}

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO dns_routes(id,gateway_device_id,domain_suffix,resolver,status) VALUES($1,$2,$3,$4,$5)`,
		item.ID,
		item.GatewayDeviceID,
		item.DomainSuffix,
		item.Resolver.String(),
		item.Status,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Repository) SetStatus(ctx context.Context, id string, status routes.Status) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE advertised_routes SET status=$2 WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return routes.ErrAdvertisementNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE dns_routes SET status=$2 WHERE id=$1`, id, status); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Repository) List(ctx context.Context, status *routes.Status) ([]routes.Advertisement, error) {
	// inet::text includes a host mask (/32 or /128); host() returns the plain
	// address required by netip.ParseAddr without discarding an IPv6 resolver.
	query := `SELECT r.id,r.gateway_device_id,r.prefix::text,host(d.resolver),d.domain_suffix,r.status,r.created_at FROM advertised_routes r JOIN dns_routes d USING(id)`
	args := []any{}
	if status != nil {
		query += ` WHERE r.status=$1`
		args = append(args, *status)
	}
	query += ` ORDER BY r.created_at,r.id`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []routes.Advertisement{}
	for rows.Next() {
		var item routes.Advertisement
		var prefix, resolver string
		if err = rows.Scan(
			&item.ID,
			&item.GatewayDeviceID,
			&prefix,
			&resolver,
			&item.DomainSuffix,
			&item.Status,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		item.Prefix, err = netip.ParsePrefix(prefix)
		if err != nil {
			return nil, err
		}
		item.Resolver, err = netip.ParseAddr(resolver)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

var _ routes.Repository = (*Repository)(nil)
