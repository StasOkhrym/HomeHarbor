package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

// Every personal credential operation holds the same account-row lock as TOTP,
// password reset and revocation. Scope admission and last-method checks cannot
// race each other across control replicas.
func (s *Repository) withAdminAccount(
	ctx context.Context,
	scope identity.AccountScope,
	operation func(pgx.Tx, identity.Account) error,
) error {
	if scope.Purpose != identity.SessionAdmin {
		return identity.ErrInvalidCredential
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	account, err := lockedAccountScope(ctx, tx, scope)
	if err != nil {
		return err
	}
	if err := operation(tx, account); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Repository) SavePersonalCredential(
	ctx context.Context,
	scope identity.AccountScope,
	value identity.NamedCredential,
) error {
	payload, err := json.Marshal(value.Credential)
	if err != nil {
		return err
	}
	transports := make([]string, len(value.Credential.Transport))
	for i, transport := range value.Credential.Transport {
		transports[i] = string(transport)
	}
	return s.withAdminAccount(ctx, scope, func(tx pgx.Tx, account identity.Account) error {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_handle=$1`, account.UserHandle).
			Scan(&count); err != nil {
			return err
		}
		if count >= identity.MaxPasskeys {
			return identity.ErrFactorLimit
		}
		_, err := tx.Exec(
			ctx,
			`INSERT INTO webauthn_credentials(credential_id,public_key,attestation_type,transport,sign_count,user_handle,credential_data,credential_name,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			value.Credential.ID,
			value.Credential.PublicKey,
			value.Credential.AttestationType,
			transports,
			value.Credential.Authenticator.SignCount,
			account.UserHandle,
			payload,
			value.Name,
			value.CreatedAt,
		)
		if err != nil {
			var conflict *pgconn.PgError
			if errors.As(err, &conflict) && conflict.Code == "23505" {
				return identity.ErrInvalidCredential
			}
			return err
		}
		return advanceAuthVersion(ctx, tx, scope.AccountID)
	})
}

func (s *Repository) UpdatePersonalCredential(
	ctx context.Context,
	scope identity.AccountScope,
	credential webauthn.Credential,
	now time.Time,
) error {
	return s.withAdminAccount(ctx, scope, func(tx pgx.Tx, account identity.Account) error {
		if err := updateCredentialData(ctx, tx, account.UserHandle, credential); err != nil {
			return err
		}

		_, err := tx.Exec(
			ctx,
			`UPDATE webauthn_credentials SET last_used_at=$3 WHERE user_handle=$1 AND credential_id=$2`,
			account.UserHandle,
			credential.ID,
			now,
		)

		return err
	})
}

func (s *Repository) FactorState(
	ctx context.Context,
	scope identity.AccountScope,
) (identity.FactorState, error) {
	state := identity.FactorState{Passkeys: []identity.PasskeyInfo{}}
	err := s.withAdminAccount(ctx, scope, func(tx pgx.Tx, account identity.Account) error {
		rows, err := tx.Query(
			ctx,
			`SELECT credential_id,credential_name,created_at,last_used_at FROM webauthn_credentials WHERE user_handle=$1 ORDER BY created_at,credential_id LIMIT $2`,
			account.UserHandle,
			identity.MaxPasskeys+1,
		)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var id []byte
			var info identity.PasskeyInfo

			if err := rows.Scan(&id, &info.Name, &info.CreatedAt, &info.LastUsedAt); err != nil {
				return err
			}

			info.ID = base64.RawURLEncoding.EncodeToString(id)
			state.Passkeys = append(state.Passkeys, info)
		}

		if err := rows.Err(); err != nil {
			return err
		}

		rows.Close()
		if len(state.Passkeys) > identity.MaxPasskeys {
			return identity.ErrSecurityStateUnavailable
		}

		return tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admin_totp WHERE account_id=$1 AND confirmed_at IS NOT NULL),(SELECT count(*) FROM recovery_codes WHERE account_id=$1 AND used_at IS NULL)`, scope.AccountID).
			Scan(&state.TOTP, &state.RecoveryCodesRemaining)
	})
	if err != nil {
		return identity.FactorState{}, err
	}

	return state, nil
}

func (s *Repository) RemovePasskey(
	ctx context.Context,
	scope identity.AccountScope,
	id []byte,
) error {
	return s.withAdminAccount(ctx, scope, func(tx pgx.Tx, account identity.Account) error {
		var exists bool

		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_handle=$1 AND credential_id=$2)`, account.UserHandle, id).
			Scan(&exists); err != nil {
			return err
		}

		if !exists {
			return identity.ErrInvalidCredential
		}

		var count int
		var totp bool

		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_handle=$1),EXISTS(SELECT 1 FROM admin_totp WHERE account_id=$2 AND confirmed_at IS NOT NULL)`, account.UserHandle, scope.AccountID).
			Scan(&count, &totp); err != nil {
			return err
		}

		if count <= 1 && !totp {
			return identity.ErrLastMFA
		}

		if _, err := tx.Exec(
			ctx,
			`DELETE FROM webauthn_credentials WHERE user_handle=$1 AND credential_id=$2`,
			account.UserHandle,
			id,
		); err != nil {
			return err
		}

		return advanceAuthVersion(ctx, tx, scope.AccountID)
	})
}
