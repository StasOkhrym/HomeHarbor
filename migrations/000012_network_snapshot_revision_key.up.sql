-- Revisions are contiguous within a network, not across unrelated networks.
-- Changing only the key preserves all signed payloads and hash chains.
ALTER TABLE network_snapshots DROP CONSTRAINT network_snapshots_pkey;
ALTER TABLE network_snapshots ADD PRIMARY KEY (network_id, revision);
