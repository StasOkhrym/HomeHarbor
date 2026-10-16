CREATE TABLE telemetry_reporters (
    device_id text PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    generation bigint NOT NULL CHECK (generation > 0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    started_at timestamptz NOT NULL,
    observed_at timestamptz
);

CREATE TABLE telemetry_observations (
    reporter_device_id text NOT NULL REFERENCES telemetry_reporters (device_id) ON DELETE CASCADE,
    subject_device_id text NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    reporter_role text NOT NULL CHECK (reporter_role IN ('client', 'gateway')),
    generation bigint NOT NULL CHECK (generation > 0),
    report_sequence bigint NOT NULL CHECK (report_sequence > 0),
    runtime_id uuid NOT NULL,
    runtime_state text NOT NULL CHECK (
        runtime_state IN ('starting', 'running', 'stopped', 'failed')
    ),
    applied_revision bigint NOT NULL CHECK (applied_revision >= 0),
    observed_at timestamptz NOT NULL,
    sample jsonb NOT NULL,
    PRIMARY KEY (reporter_device_id, subject_device_id)
);

CREATE INDEX telemetry_observed_at ON telemetry_observations (observed_at DESC);
