CREATE TABLE enrollment_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    role text NOT NULL CHECK (role IN ('client', 'gateway')),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE devices (
    id text PRIMARY KEY,
    name text NOT NULL,
    role text NOT NULL CHECK (role IN ('client', 'gateway')),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    identity_public_key text NOT NULL UNIQUE,
    wireguard_public_key text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE TABLE device_credentials (
    device_id text NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    credential_hash bytea PRIMARY KEY CHECK (octet_length(credential_hash) = 32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz
);

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_type text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE advertised_routes (
    id text PRIMARY KEY,
    gateway_device_id text NOT NULL REFERENCES devices (id),
    prefix cidr NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (gateway_device_id, prefix)
);

CREATE TABLE dns_routes (
    id text PRIMARY KEY,
    gateway_device_id text NOT NULL REFERENCES devices (id),
    domain_suffix text NOT NULL,
    resolver inet NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    UNIQUE (gateway_device_id, domain_suffix)
);

CREATE TABLE policy_rules (
    id text PRIMARY KEY,
    source_device_id text NOT NULL REFERENCES devices (id),
    destination cidr NOT NULL,
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port_from integer NOT NULL CHECK (port_from BETWEEN 1 AND 65535),
    port_to integer NOT NULL CHECK (port_to BETWEEN port_from AND 65535),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy_revisions (
    revision bigint PRIMARY KEY,
    snapshot jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE recovery_codes (
    code_hash bytea PRIMARY KEY CHECK (octet_length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_credentials (
    credential_id bytea PRIMARY KEY,
    public_key bytea NOT NULL,
    attestation_type text NOT NULL,
    transport text[] NOT NULL DEFAULT '{}',
    sign_count bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);
