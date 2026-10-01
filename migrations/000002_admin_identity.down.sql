DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS webauthn_ceremonies;
ALTER TABLE webauthn_credentials
DROP COLUMN IF EXISTS updated_at,
DROP COLUMN IF EXISTS credential_data,
DROP COLUMN IF EXISTS user_handle;
