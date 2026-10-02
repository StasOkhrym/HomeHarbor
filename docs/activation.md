# Signed activation and durable events

Invite approval creates the public device identity, profile membership, approval
record and outbox events in one DB transaction. The application workflow owns the
transaction; each module's storage adapter writes its own tables. Approval returns
public identifiers, never the device credential to the companion. An identical
root-signed approval is idempotent; a different key/profile/diff is rejected.

The node claims its credential separately. A claim requires an approved invite,
a trusted snapshot containing the exact device/key/profile and proof of possession
of the node's private identity key. Challenges are single-use Redis state. The
signed canonical challenge uses the `homeharbor/activation-claim/v1` domain and
binds network, invite, device, nonce and expiry. Private keys and invite codes
are not transmitted to control.

Claims replace credentials under a durable device lock. The unique active-device
credential index prevents concurrent claims/rotation from leaving multiple live
credentials. After a lost claim response, a fresh challenge creates a replacement
and invalidates the previous credential. Revoked devices cannot claim. The node
reuses its existing key material and saves the received credential atomically.

HTTP challenge/claim endpoints live under `/api/v1/invites/{id}`. Missing signed
publication is a conflict; invalid/replayed proof is a client error. Redis outage
is unavailable, not an invalid identity. Application services and challenge
repositories are constructor dependencies; there is no process-local production
fallback or credential-in-approval compatibility path.

Outbox IDs stay stable across retries. Events contain public aggregate/action/time,
not credentials. Audit delivery acknowledges only after durable consumption;
consumers are idempotent and dispatcher failure affects readiness. DB/Redis
integration tests cover approval rollback, concurrent approval/claim, lost HTTP
responses, replay and the single-active-credential invariant. These contracts do
not prove the separate deployed Linux tunnel path.
