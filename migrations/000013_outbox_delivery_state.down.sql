DROP INDEX event_outbox_degraded_idx;
DROP INDEX event_outbox_pending_idx;
ALTER TABLE event_outbox DROP COLUMN quarantined_at;
ALTER TABLE event_outbox DROP COLUMN next_attempt_at;
CREATE INDEX event_outbox_pending_idx ON event_outbox (id) WHERE published_at IS NULL;
