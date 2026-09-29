ALTER TABLE webauthn_credentials
    ADD COLUMN user_handle bytea NOT NULL DEFAULT ''::bytea,
    ADD COLUMN credential_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE webauthn_ceremonies (
    ceremony_id_hash bytea PRIMARY KEY CHECK (octet_length(ceremony_id_hash) = 32),
    kind text NOT NULL CHECK (kind IN ('bootstrap', 'login')),
    payload_ciphertext bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX admin_sessions_active_idx
    ON admin_sessions (expires_at)
    WHERE revoked_at IS NULL;
