// Package storage persists only sealed notification payloads and public delivery
// state. Bind shares a caller's transaction without owning its commit or rollback.
package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
)

type database interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type Repository struct{ db database }

func New(pool *pgxpool.Pool) *Repository {
	if pool == nil {
		return &Repository{}
	}

	return &Repository{db: pool}
}
func Bind(tx pgx.Tx) *Repository { return &Repository{db: tx} }

func (r *Repository) Enqueue(ctx context.Context, p notifications.Prepared) error {
	if r.db == nil {
		return notifications.ErrUnavailable
	}
	if p.ID == "" || p.AccountID == "" || len(p.Ciphertext) < 49 || len(p.Ciphertext) > 8192 ||
		p.CreatedAt.IsZero() ||
		!p.ExpiresAt.After(p.CreatedAt) {
		return notifications.ErrInvalidPayload
	}

	var id string

	err := r.db.QueryRow(ctx, `INSERT INTO notification_deliveries(id,account_id,kind,private_payload,logical_fingerprint,created_at,expires_at,next_attempt_at)
 VALUES($1,$2,$3,$4,$5,$6,$7,$6)
 ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id
 WHERE notification_deliveries.logical_fingerprint=EXCLUDED.logical_fingerprint
 RETURNING id`, p.ID, p.AccountID, p.Kind, p.Ciphertext, p.Fingerprint[:], p.CreatedAt, p.ExpiresAt).
		Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return notifications.ErrLogicalConflict
	}
	if err != nil {
		return notifications.ErrUnavailable
	}

	return nil
}

// Claim uses a short atomic statement; SMTP must run after this returns, without
// keeping a database transaction open. Each reclaim gets a new random fence.
func (r *Repository) Claim(ctx context.Context) (notifications.Delivery, bool, error) {
	if r.db == nil {
		return notifications.Delivery{}, false, notifications.ErrUnavailable
	}

	token, err := uuid.NewRandom()
	if err != nil {
		return notifications.Delivery{}, false, notifications.ErrUnavailable
	}

	var delivery notifications.Delivery
	var fingerprint []byte

	err = r.db.QueryRow(ctx, `WITH terminal_candidates AS (
 SELECT id FROM notification_deliveries WHERE status='pending' AND (expires_at<=now() OR (attempts>=8 AND (lease_token IS NULL OR leased_until<=now())))
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 100
 ), terminal AS (
 UPDATE notification_deliveries n SET status=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'failed' END,private_payload=NULL,lease_token=NULL,leased_until=NULL,
 next_attempt_at=NULL,completed_at=now(),last_error_code=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'attempts_exhausted' END
 FROM terminal_candidates e WHERE n.id=e.id
 ), candidate AS (
 SELECT id FROM notification_deliveries WHERE status='pending' AND created_at<=now() AND expires_at>now()
 AND next_attempt_at<=now() AND (lease_token IS NULL OR leased_until<=now()) AND attempts<8
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
 ) UPDATE notification_deliveries n SET lease_token=$1,leased_until=now()+interval '45 seconds',attempts=attempts+1
 FROM candidate c WHERE n.id=c.id
 RETURNING n.id,n.account_id,n.kind,n.private_payload,n.logical_fingerprint,n.created_at,n.expires_at,n.lease_token,n.attempts`, token.String()).Scan(
		&delivery.ID, &delivery.AccountID, &delivery.Kind, &delivery.Ciphertext, &fingerprint, &delivery.CreatedAt, &delivery.ExpiresAt, &delivery.LeaseToken, &delivery.Attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return notifications.Delivery{}, false, nil
	}
	if err != nil {
		return notifications.Delivery{}, false, notifications.ErrUnavailable
	}
	if len(fingerprint) != 32 {
		return notifications.Delivery{}, false, notifications.ErrInvalidPayload
	}

	copy(delivery.Fingerprint[:], fingerprint)
	return delivery, true, nil
}

func (r *Repository) Finish(
	ctx context.Context,
	d notifications.Delivery,
	outcome notifications.Outcome,
) error {
	if r.db == nil {
		return notifications.ErrUnavailable
	}

	switch outcome {
	case notifications.DeliverySent,
		notifications.RetryDelivery,
		notifications.PermanentFailure,
		notifications.InvalidPayload:
	default:
		return notifications.ErrInvalidPayload
	}

	result, err := r.db.Exec(ctx, `UPDATE notification_deliveries SET
 status=CASE WHEN $3='sent' THEN 'sent' WHEN expires_at<=now() THEN 'expired'
 WHEN $3='retry' AND attempts<8 THEN 'pending' ELSE 'failed' END,
 private_payload=CASE WHEN $3='retry' AND attempts<8 AND expires_at>now() THEN private_payload ELSE NULL END,
 next_attempt_at=CASE WHEN $3='retry' AND attempts<8 AND expires_at>now()
 THEN now()+make_interval(secs=>LEAST(3600,5*power(2,attempts-1))) ELSE NULL END,
 completed_at=CASE WHEN $3='retry' AND attempts<8 AND expires_at>now() THEN NULL ELSE now() END,
 lease_token=NULL,leased_until=NULL,
 last_error_code=CASE WHEN $3='sent' THEN NULL WHEN expires_at<=now() THEN 'expired'
 WHEN $3='retry' AND attempts>=8 THEN 'attempts_exhausted' WHEN $3='retry' THEN 'smtp_temporary'
 WHEN $3='permanent_failure' THEN 'smtp_permanent' ELSE 'invalid_payload' END
 WHERE id=$1 AND status='pending' AND lease_token=$2 AND attempts=$4`, d.ID, d.LeaseToken, string(outcome), d.Attempt)
	if err != nil {
		return notifications.ErrUnavailable
	}
	if result.RowsAffected() != 1 {
		return notifications.ErrLeaseLost
	}

	return nil
}

// CancelPending scrubs obsolete credentials and fences any outstanding worker.
// A message already accepted by SMTP cannot be recalled; its token is separately
// invalidated in the same account transaction. An empty kind cancels all kinds.
func (r *Repository) CancelPending(
	ctx context.Context,
	accountID string,
	kind notifications.Kind,
) error {
	if r.db == nil {
		return notifications.ErrUnavailable
	}
	if accountID == "" {
		return notifications.ErrInvalidPayload
	}

	switch kind {
	case "",
		notifications.AdminInvitation,
		notifications.EmailVerification,
		notifications.PasswordReset,
		notifications.SecurityNotice,
		notifications.SMTPTest:
	default:
		return notifications.ErrInvalidPayload
	}

	_, err := r.db.Exec(
		ctx,
		`UPDATE notification_deliveries SET status='cancelled',private_payload=NULL,next_attempt_at=NULL,lease_token=NULL,leased_until=NULL,completed_at=now(),last_error_code='cancelled' WHERE account_id=$1 AND status='pending' AND ($2::text='' OR kind=$2)`,
		accountID,
		string(kind),
	)
	if err != nil {
		return notifications.ErrUnavailable
	}

	return nil
}
