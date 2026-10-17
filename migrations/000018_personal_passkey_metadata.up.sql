ALTER TABLE webauthn_credentials
ADD COLUMN credential_name text NOT NULL DEFAULT 'Passkey'
CHECK (length(credential_name) BETWEEN 1 AND 80 AND credential_name = btrim(credential_name));

-- Existing keys keep their original JSON, handles and counters. No historical
-- use timestamp is inferred from credential creation or migration time.
ALTER TABLE webauthn_credentials ADD COLUMN last_used_at timestamptz;
