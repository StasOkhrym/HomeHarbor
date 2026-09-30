-- Fail with existing duplicates intact. Operators must explicitly resolve
-- historical multiple credentials before retrying this migration.
CREATE UNIQUE INDEX device_credentials_one_active_per_device
    ON device_credentials(device_id) WHERE revoked_at IS NULL;
