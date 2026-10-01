-- NULL identities preserve distinct direct authentication records. Outbox
-- identities are stable across redelivery and enforce idempotency durably.
ALTER TABLE audit_events ADD COLUMN event_id text;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_delivery_id UNIQUE (event_id);
