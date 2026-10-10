ALTER TABLE event_outbox ADD COLUMN next_attempt_at timestamptz;
ALTER TABLE event_outbox ADD COLUMN quarantined_at timestamptz;
DROP INDEX event_outbox_pending_idx;
CREATE INDEX event_outbox_pending_idx ON event_outbox (next_attempt_at, id)
WHERE published_at IS NULL AND quarantined_at IS NULL;
CREATE INDEX event_outbox_degraded_idx ON event_outbox (id)
WHERE published_at IS NULL AND (attempts > 0 OR quarantined_at IS NOT NULL);
