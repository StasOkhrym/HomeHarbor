CREATE TABLE services (
    id text PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('web', 'native')),
    url text NOT NULL,
    native_url text,
    health_url text,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_profiles (
    id text PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_profile_services (
    profile_id text NOT NULL REFERENCES access_profiles (id) ON DELETE CASCADE,
    service_id text NOT NULL REFERENCES services (id) ON DELETE RESTRICT,
    PRIMARY KEY (profile_id, service_id)
);

CREATE TABLE access_profile_devices (
    profile_id text NOT NULL REFERENCES access_profiles (id) ON DELETE CASCADE,
    device_id text NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    PRIMARY KEY (profile_id, device_id)
);
