CREATE TABLE admin_mail_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    account_id text NOT NULL REFERENCES admin_accounts (account_id),
    email text NOT NULL CHECK (
        length(email) BETWEEN 3 AND 254 AND email = lower(btrim(email))
    ),
    auth_version bigint NOT NULL CHECK (auth_version > 0),
    purpose text NOT NULL CHECK (
        purpose IN ('admin_invitation', 'email_verification', 'password_reset')
    ),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    UNIQUE (account_id, purpose),
    CONSTRAINT admin_mail_token_lifetime CHECK (
        expires_at > created_at
        AND (
            (purpose = 'password_reset' AND expires_at <= created_at + interval '15 minutes')
            OR (
                purpose IN ('admin_invitation', 'email_verification')
                AND expires_at <= created_at + interval '24 hours'
            )
        )
    ),
    CONSTRAINT admin_mail_token_consumption_time CHECK (
        used_at IS NULL OR (used_at >= created_at AND used_at < expires_at)
    )
);
