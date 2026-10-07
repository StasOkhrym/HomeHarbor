package storage

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

func (s *Repository) Replace(
	ctx context.Context,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	return s.replace(ctx, rules, compiler, nil)
}

func (s *Repository) ReplaceIfRevision(
	ctx context.Context,
	revision uint64,
	rules []acl.Rule,
	compiler acl.Compiler,
) (acl.Snapshot, error) {
	return s.replace(ctx, rules, compiler, &revision)
}

func (s *Repository) replace(
	ctx context.Context,
	rules []acl.Rule,
	compiler acl.Compiler,
	expected *uint64,
) (acl.Snapshot, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return acl.Snapshot{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serializing writers keeps revision allocation and the corresponding
	// immutable snapshot in the same transaction across control-plane replicas.
	if _, err = tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtext('homeharbor_policy'))`,
	); err != nil {
		return acl.Snapshot{}, err
	}

	var revision uint64

	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(revision),0)+1 FROM policy_revisions`).
		Scan(&revision); err != nil {
		return acl.Snapshot{}, err
	}

	// The advisory lock also serializes API writers. Checking here, not in
	// the HTTP handler, closes the race between preview confirmation and write.
	if expected != nil && revision-1 != *expected {
		return acl.Snapshot{}, policy.ErrRevisionConflict
	}

	snapshot, err := compiler.Compile(revision, rules)
	if err != nil {
		return acl.Snapshot{}, err
	}

	// policy_rules is the current materialized view; policy_revisions remains
	// append-only so agents can reconcile and operators can inspect history.
	if _, err = tx.Exec(ctx, `DELETE FROM policy_rules`); err != nil {
		return acl.Snapshot{}, err
	}

	for _, rule := range snapshot.Rules {
		if _, err = tx.Exec(
			ctx,
			`INSERT INTO policy_rules(id,source_device_id,destination,protocol,port_from,port_to) VALUES($1,$2,$3,$4,$5,$6)`,
			rule.ID,
			rule.SourceDeviceID,
			rule.Destination.String(),
			rule.Protocol,
			rule.PortFrom,
			rule.PortTo,
		); err != nil {
			return acl.Snapshot{}, err
		}
	}

	payload, err := json.Marshal(snapshot)
	if err != nil {
		return acl.Snapshot{}, err
	}

	if _, err = tx.Exec(
		ctx,
		`INSERT INTO policy_revisions(revision,snapshot) VALUES($1,$2)`,
		revision,
		payload,
	); err != nil {
		return acl.Snapshot{}, err
	}

	if err = tx.Commit(ctx); err != nil {
		return acl.Snapshot{}, err
	}

	return snapshot, nil
}

func (s *Repository) Latest(ctx context.Context) (acl.Snapshot, error) {
	var payload []byte

	err := s.pool.QueryRow(ctx, `SELECT snapshot FROM policy_revisions ORDER BY revision DESC LIMIT 1`).
		Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return acl.Snapshot{DefaultAction: acl.ActionDeny, Rules: []acl.Rule{}}, nil
	}
	if err != nil {
		return acl.Snapshot{}, err
	}

	var snapshot acl.Snapshot

	if err = json.Unmarshal(payload, &snapshot); err != nil {
		return acl.Snapshot{}, err
	}

	return snapshot, nil
}

var _ policy.Repository = (*Repository)(nil)
