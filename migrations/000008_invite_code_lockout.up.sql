ALTER TABLE invite_records
    DROP CONSTRAINT invite_records_status_check;

ALTER TABLE invite_records
    ADD COLUMN failed_code_attempts integer NOT NULL DEFAULT 0
        CHECK (failed_code_attempts BETWEEN 0 AND 5),
    ADD COLUMN blocked_at timestamptz;

ALTER TABLE invite_records
    ADD CONSTRAINT invite_records_status_check
        CHECK (status IN ('pending', 'approved', 'blocked'));
