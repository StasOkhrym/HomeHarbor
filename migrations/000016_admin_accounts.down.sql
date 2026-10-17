ALTER TABLE webauthn_credentials DROP CONSTRAINT webauthn_account_handle_fk;
ALTER TABLE recovery_codes DROP CONSTRAINT recovery_codes_pkey;
ALTER TABLE recovery_codes ADD PRIMARY KEY (code_hash);
ALTER TABLE recovery_codes DROP COLUMN account_id;
DROP TABLE admin_accounts;
