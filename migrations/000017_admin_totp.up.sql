CREATE TABLE admin_totp (
    account_id text PRIMARY KEY REFERENCES admin_accounts (account_id),
    totp_id uuid NOT NULL UNIQUE,
    enrollment_auth_version bigint NOT NULL CHECK (enrollment_auth_version > 0),
    seed_ciphertext bytea NOT NULL CHECK (octet_length(seed_ciphertext) BETWEEN 49 AND 256),
    created_at timestamptz NOT NULL,
    pending_expires_at timestamptz,
    confirmed_at timestamptz,
    last_used_step bigint NOT NULL DEFAULT -1 CHECK (last_used_step >= -1),
    CONSTRAINT totp_pending_or_confirmed CHECK (
        (
            confirmed_at IS NULL
            AND pending_expires_at IS NOT NULL
            AND pending_expires_at > created_at
            AND pending_expires_at <= created_at + interval '10 minutes'
            AND last_used_step = -1
        )
        OR (
            confirmed_at IS NOT NULL
            AND confirmed_at >= created_at
            AND pending_expires_at IS NULL
            AND last_used_step >= 0
        )
    )
);
