package identity

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) SaveRecoveryCodes(ctx context.Context, codes []RecoveryCode) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Rotation is a set replacement, not an append. Deleting and inserting in
	// one transaction prevents old and new emergency credentials overlapping.
	if _, err = tx.Exec(ctx, `DELETE FROM recovery_codes`); err != nil {
		return err
	}
	for _, code := range codes {
		if _, err = tx.Exec(ctx, `INSERT INTO recovery_codes(code_hash,created_at) VALUES($1,$2)`, code.Hash[:], code.CreatedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) HasCredentials(ctx context.Context) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webauthn_credentials)`).Scan(&exists)
	return exists, err
}

func (s *PostgresStore) Credentials(ctx context.Context, userHandle []byte) ([]webauthn.Credential, error) {
	rows, err := s.pool.Query(ctx, `SELECT credential_data FROM webauthn_credentials WHERE user_handle=$1 ORDER BY created_at`, userHandle)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []webauthn.Credential{}
	for rows.Next() {
		var payload []byte
		if err = rows.Scan(&payload); err != nil {
			return nil, err
		}
		var credential webauthn.Credential
		if err = json.Unmarshal(payload, &credential); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (s *PostgresStore) Credential(ctx context.Context, userHandle, credentialID []byte) (webauthn.Credential, error) {
	var payload []byte
	err := s.pool.QueryRow(ctx, `SELECT credential_data FROM webauthn_credentials WHERE user_handle=$1 AND credential_id=$2`, userHandle, credentialID).Scan(&payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return webauthn.Credential{}, ErrInvalidCredential
	}
	if err != nil {
		return webauthn.Credential{}, err
	}
	var credential webauthn.Credential
	if err = json.Unmarshal(payload, &credential); err != nil {
		return webauthn.Credential{}, err
	}
	return credential, nil
}

func (s *PostgresStore) SaveCredential(ctx context.Context, userHandle []byte, credential webauthn.Credential) error {
	payload, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	transports := make([]string, len(credential.Transport))
	for index, transport := range credential.Transport {
		transports[index] = string(transport)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A table lock serializes the empty-set check with the first insert. Row
	// locks cannot protect an absence, which is the state bootstrap relies on.
	if _, err = tx.Exec(ctx, `LOCK TABLE webauthn_credentials IN EXCLUSIVE MODE`); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_handle=$1)`, userHandle).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrBootstrapClosed
	}
	if _, err = tx.Exec(ctx, `INSERT INTO webauthn_credentials(credential_id,public_key,attestation_type,transport,sign_count,user_handle,credential_data) VALUES($1,$2,$3,$4,$5,$6,$7)`, credential.ID, credential.PublicKey, credential.AttestationType, transports, credential.Authenticator.SignCount, userHandle, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UpdateCredential(ctx context.Context, userHandle []byte, credential webauthn.Credential) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedPayload []byte
	if err = tx.QueryRow(ctx, `SELECT credential_data FROM webauthn_credentials WHERE user_handle=$1 AND credential_id=$2 FOR UPDATE`, userHandle, credential.ID).Scan(&storedPayload); errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCredential
	} else if err != nil {
		return err
	}
	var stored webauthn.Credential
	if err = json.Unmarshal(storedPayload, &stored); err != nil {
		return err
	}
	// A non-zero counter must move strictly forward. Holding the row lock makes
	// this comparison valid even when two login responses arrive concurrently.
	if stored.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= stored.Authenticator.SignCount {
		return ErrInvalidCredential
	}
	payload, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE webauthn_credentials SET credential_data=$3,sign_count=$4,updated_at=now() WHERE user_handle=$1 AND credential_id=$2`, userHandle, credential.ID, payload, credential.Authenticator.SignCount); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) SaveCeremony(ctx context.Context, ceremony Ceremony) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO webauthn_ceremonies(ceremony_id_hash,kind,payload_ciphertext,expires_at) VALUES($1,$2,$3,$4)`, ceremony.IDHash[:], ceremony.Kind, ceremony.PayloadCiphertext, ceremony.ExpiresAt)
	return err
}

func (s *PostgresStore) ConsumeCeremony(ctx context.Context, hash [32]byte, now time.Time) (Ceremony, error) {
	var ceremony Ceremony
	var storedHash []byte
	// Expiry, replay check, and consumption are one statement so no second
	// process can validate the same browser challenge concurrently.
	err := s.pool.QueryRow(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$2 WHERE ceremony_id_hash=$1 AND consumed_at IS NULL AND expires_at>$2 RETURNING ceremony_id_hash,kind,payload_ciphertext,expires_at,consumed_at`, hash[:], now).Scan(&storedHash, &ceremony.Kind, &ceremony.PayloadCiphertext, &ceremony.ExpiresAt, &ceremony.ConsumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Ceremony{}, ErrInvalidCeremony
	}
	if err != nil {
		return Ceremony{}, err
	}
	copy(ceremony.IDHash[:], storedHash)
	return ceremony, nil
}

func (s *PostgresStore) ConsumeRecoveryCode(ctx context.Context, hash [32]byte, now time.Time) error {
	// The predicate and update execute as one statement, so concurrent replicas
	// cannot both observe an unused code before either marks it consumed.
	tag, err := s.pool.Exec(ctx, `UPDATE recovery_codes SET used_at=$2 WHERE code_hash=$1 AND used_at IS NULL`, hash[:], now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidCredential
	}
	return nil
}

func (s *PostgresStore) SaveSession(ctx context.Context, session Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO admin_sessions(token_hash,created_at,expires_at) VALUES($1,$2,$3)`, session.Hash[:], session.CreatedAt, session.ExpiresAt)
	return err
}

func (s *PostgresStore) Session(ctx context.Context, hash [32]byte) (Session, error) {
	var session Session
	var storedHash []byte
	err := s.pool.QueryRow(ctx, `SELECT token_hash,created_at,expires_at,revoked_at FROM admin_sessions WHERE token_hash=$1`, hash[:]).Scan(&storedHash, &session.CreatedAt, &session.ExpiresAt, &session.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrInvalidCredential
	}
	if err != nil {
		return Session{}, err
	}
	copy(session.Hash[:], storedHash)
	return session, nil
}

func (s *PostgresStore) RevokeSession(ctx context.Context, hash [32]byte, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE admin_sessions SET revoked_at=COALESCE(revoked_at,$2) WHERE token_hash=$1`, hash[:], now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrInvalidCredential
	}
	return nil
}
