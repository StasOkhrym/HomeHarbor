ALTER TABLE invite_records
    DROP CONSTRAINT IF EXISTS invite_records_wireguard_public_key_length,
    DROP COLUMN IF EXISTS wireguard_public_key;
