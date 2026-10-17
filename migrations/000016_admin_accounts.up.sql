CREATE TABLE admin_accounts (
    account_id text PRIMARY KEY CHECK (length(account_id) BETWEEN 1 AND 128),
    email text UNIQUE,
    role text NOT NULL CHECK (role IN ('owner', 'admin')),
    status text NOT NULL CHECK (status IN ('setup', 'invited', 'active', 'revoked')),
    auth_version bigint NOT NULL DEFAULT 1 CHECK (auth_version > 0),
    user_handle bytea NOT NULL UNIQUE CHECK (octet_length(user_handle) BETWEEN 1 AND 64),
    password_hash text CHECK (password_hash IS NULL OR length(password_hash) BETWEEN 1 AND 512),
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT account_email_canonical CHECK (
        email IS NULL OR (length(email) BETWEEN 3 AND 254 AND email = lower(btrim(email)))
    ),
    CONSTRAINT sole_owner_identity CHECK (
        (account_id = '00000000-0000-4000-8000-000000000001') = (role = 'owner')
    ),
    CONSTRAINT owner_cannot_be_revoked CHECK (
        role <> 'owner' OR status IN ('setup', 'active')
    ),
    CONSTRAINT owner_retains_passkey_handle CHECK (
        role <> 'owner' OR user_handle = convert_to('homeharbor-admin-v1', 'UTF8')
    ),
    CONSTRAINT active_account_requires_password CHECK (
        status <> 'active' OR (email IS NOT NULL AND password_hash IS NOT NULL)
    )
);

INSERT INTO admin_accounts (account_id, role, status, user_handle)
VALUES (
    '00000000-0000-4000-8000-000000000001',
    'owner',
    'setup',
    convert_to('homeharbor-admin-v1', 'UTF8')
);

-- The existing stable handle establishes credential ownership without replacing
-- credential IDs, public keys, sign counters or authenticator user handles.
ALTER TABLE webauthn_credentials
ADD CONSTRAINT webauthn_account_handle_fk FOREIGN KEY (user_handle)
REFERENCES admin_accounts (user_handle);

ALTER TABLE recovery_codes
ADD COLUMN account_id text NOT NULL DEFAULT '00000000-0000-4000-8000-000000000001'
REFERENCES admin_accounts (account_id);

-- Legacy rows belong to the sole owner; every future write must name its account.
ALTER TABLE recovery_codes ALTER COLUMN account_id DROP DEFAULT;
ALTER TABLE recovery_codes DROP CONSTRAINT recovery_codes_pkey;
ALTER TABLE recovery_codes ADD PRIMARY KEY (account_id, code_hash);
