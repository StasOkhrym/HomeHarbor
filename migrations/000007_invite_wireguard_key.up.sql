-- Legacy pending invites did not carry a WireGuard public key. Keep those
-- rows readable for audit/recovery, but activation rejects them until a new
-- invite proof supplies the missing public identity.
ALTER TABLE invite_records
ADD COLUMN wireguard_public_key bytea;

ALTER TABLE invite_records
ADD CONSTRAINT invite_records_wireguard_public_key_length
CHECK (wireguard_public_key IS NULL OR octet_length(wireguard_public_key) = 32);
