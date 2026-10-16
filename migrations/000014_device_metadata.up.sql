CREATE TABLE device_metadata (
    device_id text PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    platform text NOT NULL CHECK (
        platform IN ('ios', 'macos', 'windows', 'linux', 'android', 'unknown')
    ),
    os_version text NOT NULL DEFAULT '' CHECK (octet_length(os_version) <= 64),
    client_version text NOT NULL DEFAULT '' CHECK (octet_length(client_version) <= 64),
    reported_at timestamptz NOT NULL
);

CREATE INDEX audit_actor_identity ON audit_events (actor_type, actor_id, id DESC);
CREATE INDEX audit_target_identity ON audit_events (target_type, target_id, id DESC);
