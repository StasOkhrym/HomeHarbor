package storage

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
)

// EnqueueSMTPTest requires a bound transaction whose caller retains the owner
// account lock. The SQL clock determines the shared one-minute issuance limit.
func (r *Repository) EnqueueSMTPTest(ctx context.Context, p notifications.Prepared) error {
	if _, ok := r.db.(pgx.Tx); !ok {
		return notifications.ErrUnavailable
	}

	if p.Kind != notifications.SMTPTest {
		return notifications.ErrInvalidPayload
	}

	var recent bool

	if err := r.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM notification_deliveries WHERE account_id=$1 AND kind='smtp_test' AND created_at>=now()-interval '1 minute')`, p.AccountID).
		Scan(&recent); err != nil {
		return notifications.ErrUnavailable
	}

	if recent {
		return notifications.ErrRateLimited
	}

	return r.Enqueue(ctx, p)
}

func (r *Repository) LastSMTPTest(
	ctx context.Context,
	accountID string,
) (notifications.TestStatus, error) {
	if r.db == nil {
		return notifications.TestStatus{}, notifications.ErrUnavailable
	}

	var state notifications.TestStatus
	var created time.Time

	err := r.db.QueryRow(ctx, `SELECT status,attempts,created_at,COALESCE(last_error_code,'') FROM notification_deliveries WHERE account_id=$1 AND kind='smtp_test' ORDER BY created_at DESC,id DESC LIMIT 1`, accountID).
		Scan(&state.State, &state.Attempts, &created, &state.LastErrorCode)
	if errors.Is(err, pgx.ErrNoRows) {
		return notifications.TestStatus{State: "never"}, nil
	}
	if err != nil {
		return notifications.TestStatus{}, notifications.ErrUnavailable
	}

	state.CreatedAt = &created

	return state, nil
}
