CREATE TABLE notification_deliveries (
    id uuid PRIMARY KEY,
    account_id text NOT NULL REFERENCES admin_accounts (account_id),
    kind text NOT NULL CHECK (
        kind IN (
            'admin_invitation',
            'email_verification',
            'password_reset',
            'security_notice',
            'smtp_test'
        )
    ),
    private_payload bytea CHECK (octet_length(private_payload) BETWEEN 49 AND 8192),
    logical_fingerprint bytea NOT NULL CHECK (octet_length(logical_fingerprint) = 32),
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'sent', 'failed', 'expired', 'cancelled')
    ),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    next_attempt_at timestamptz,
    lease_token uuid,
    leased_until timestamptz,
    completed_at timestamptz,
    last_error_code text CHECK (
        last_error_code IN (
            'expired', 'cancelled', 'attempts_exhausted',
            'smtp_temporary', 'smtp_permanent', 'invalid_payload'
        )
    ),
    CONSTRAINT notification_bounded_lifetime CHECK (
        expires_at > created_at AND expires_at <= created_at + interval '24 hours'
    ),
    CONSTRAINT notification_complete_lease CHECK (
        (lease_token IS NULL) = (leased_until IS NULL)
    ),
    CONSTRAINT notification_private_payload_lifecycle CHECK (
        (
            status = 'pending'
            AND private_payload IS NOT NULL
            AND next_attempt_at IS NOT NULL
            AND completed_at IS NULL
        )
        OR (
            status <> 'pending'
            AND private_payload IS NULL
            AND next_attempt_at IS NULL
            AND completed_at IS NOT NULL
            AND lease_token IS NULL
            AND leased_until IS NULL
        )
    )
);

CREATE INDEX notification_deliveries_pending
ON notification_deliveries (next_attempt_at, created_at, id)
WHERE status = 'pending';

CREATE INDEX notification_deliveries_account_status
ON notification_deliveries (account_id, status);
