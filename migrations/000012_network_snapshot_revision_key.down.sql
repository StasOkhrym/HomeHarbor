-- Downgrade fails if distinct networks share revisions; never delete signed
-- history to make a legacy schema fit. An operator must resolve that explicitly.
ALTER TABLE network_snapshots DROP CONSTRAINT network_snapshots_pkey;
ALTER TABLE network_snapshots ADD PRIMARY KEY (revision);
