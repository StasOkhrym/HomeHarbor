CREATE TABLE network_snapshots (
    network_id text NOT NULL,
    revision bigint PRIMARY KEY,
    envelope_version integer NOT NULL,
    key_id text NOT NULL,
    payload bytea NOT NULL,
    hash bytea NOT NULL CHECK (octet_length(hash) = 32),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    created_at timestamptz NOT NULL
);
