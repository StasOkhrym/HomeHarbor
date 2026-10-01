CREATE TABLE invite_records (
    invite_id text PRIMARY KEY,
    profile_id text NOT NULL REFERENCES access_profiles (id),
    device_id text NOT NULL,
    device_public_key bytea NOT NULL CHECK (octet_length(device_public_key) = 32),
    permit_version integer NOT NULL,
    permit_key_id text NOT NULL,
    permit_payload bytea NOT NULL,
    permit_signature bytea NOT NULL CHECK (octet_length(permit_signature) = 64),
    proof_version integer NOT NULL,
    proof_device_public_key bytea NOT NULL CHECK (octet_length(proof_device_public_key) = 32),
    proof_code_digest bytea NOT NULL CHECK (octet_length(proof_code_digest) = 32),
    proof_signature bytea NOT NULL CHECK (octet_length(proof_signature) = 64),
    proof_device_signature bytea NOT NULL CHECK (octet_length(proof_device_signature) = 64),
    status text NOT NULL CHECK (status IN ('pending', 'approved')),
    created_at timestamptz NOT NULL,
    approved_at timestamptz
);

CREATE INDEX invite_records_status_created_at_idx ON invite_records (status, created_at);
