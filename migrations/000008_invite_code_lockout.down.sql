ALTER TABLE invite_records
    DROP CONSTRAINT invite_records_status_check;

ALTER TABLE invite_records
    DROP COLUMN blocked_at,
    DROP COLUMN failed_code_attempts;

ALTER TABLE invite_records
    ADD CONSTRAINT invite_records_status_check
        CHECK (status IN ('pending', 'approved'));
