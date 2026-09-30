package storage

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }
func (s *Repository) Replace(ctx context.Context, rules []policy.Rule, compiler policy.Compiler) (policy.Snapshot, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return policy.Snapshot{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Serializing writers keeps revision allocation and the corresponding
	// immutable snapshot in the same transaction across control-plane replicas.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('go_tunnels_policy'))`); err != nil {
		return policy.Snapshot{}, err
	}
	var revision uint64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(revision),0)+1 FROM policy_revisions`).Scan(&revision); err != nil {
		return policy.Snapshot{}, err
	}
	snapshot, err := compiler.Compile(revision, rules)
	if err != nil {
		return policy.Snapshot{}, err
	}
	// policy_rules is the current materialized view; policy_revisions remains
	// append-only so agents can reconcile and operators can inspect history.
	if _, err = tx.Exec(ctx, `DELETE FROM policy_rules`); err != nil {
		return policy.Snapshot{}, err
	}
	for _, rule := range snapshot.Rules {
		if _, err = tx.Exec(ctx, `INSERT INTO policy_rules(id,source_device_id,destination,protocol,port_from,port_to) VALUES($1,$2,$3,$4,$5,$6)`, rule.ID, rule.SourceDeviceID, rule.Destination.String(), rule.Protocol, rule.PortFrom, rule.PortTo); err != nil {
			return policy.Snapshot{}, err
		}
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return policy.Snapshot{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO policy_revisions(revision,snapshot) VALUES($1,$2)`, revision, payload); err != nil {
		return policy.Snapshot{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return policy.Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Repository) Latest(ctx context.Context) (policy.Snapshot, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `SELECT snapshot FROM policy_revisions ORDER BY revision DESC LIMIT 1`).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return policy.Snapshot{DefaultAction: policy.ActionDeny, Rules: []policy.Rule{}}, nil
	}
	if err != nil {
		return policy.Snapshot{}, err
	}
	var snapshot policy.Snapshot
	if err = json.Unmarshal(payload, &snapshot); err != nil {
		return policy.Snapshot{}, err
	}
	return snapshot, nil
}

var _ policy.Repository = (*Repository)(nil)
