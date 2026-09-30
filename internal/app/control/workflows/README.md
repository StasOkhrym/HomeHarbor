# Activation integration contract

Approval creates public device identity, profile membership, invite approval,
and two outbox events in one PostgreSQL transaction. Approval returns
`invites.ApprovalResult` with only `invite_id`, `device_id`, `profile_id`, and
`status` in JSON. Repeating the same root-signed exact diff succeeds without
new writes; any differing identity/profile/key is rejected even after approval.
There is no `ActivationResult` alias or `WithActivator` fallback.

Credential claims require an approved invite and a root-verified snapshot for
the configured network containing the exact device identity, standard WireGuard
key, and profile membership. Credentials are issued only after Ed25519
possession proof, stored as SHA-256 hashes, and replaced under a durable device
lock. Each successful replacement revokes all previous credentials atomically.
Revoked devices cannot claim. WireGuard strings use `wgtypes.Key.String()` both
in the workflow and companion snapshot publication.

## Exact wiring APIs

```go
// github.com/sokhrym/go-tunnels/internal/app/control/storage
NewActivationUnitOfWork(pool *pgxpool.Pool) *ActivationUnitOfWork
AppendEvent(ctx context.Context, tx pgx.Tx, event devices.Event) error

// github.com/sokhrym/go-tunnels/internal/app/control/workflows
NewActivation(
    uow ActivationUnitOfWork,
    records InviteReader,
    snapshots SnapshotReader,
    challenges ChallengeRepository,
    root ed25519.PublicKey,
    network string,
    now func() time.Time,
    random io.Reader,
) *Activation

(*Activation).ApproveSigned(context.Context, invite.SignedApproval) (invites.ApprovalResult, error)
(*Activation).Challenge(context.Context, string) (ClaimChallenge, error)
(*Activation).Claim(context.Context, string, ClaimProof) (ClaimResult, error)
SignClaim(ClaimChallenge, ed25519.PrivateKey) (ClaimProof, error)

// github.com/sokhrym/go-tunnels/internal/control/invites
WithApprovalWorkflow(ApprovalWorkflow) Option

// github.com/sokhrym/go-tunnels/internal/control/devices/storage
New(pool *pgxpool.Pool, appender ...EventAppender) *Repository
// Production must supply workflowstorage.AppendEvent; omission fails closed.

// github.com/sokhrym/go-tunnels/internal/control/devices
WithPublicationStrategy(PublicationStrategy) Option
// Production chooses devices.TransactionalOutbox{}; no WithPublisher fallback.

// github.com/sokhrym/go-tunnels/internal/control/httpapi
NewActivationHandler(ActivationChallenger, ActivationClaimer) *ActivationHandler
(*ActivationHandler).Challenge(http.ResponseWriter, *http.Request)
(*ActivationHandler).Claim(http.ResponseWriter, *http.Request)

// github.com/sokhrym/go-tunnels/internal/node
PrepareInviteProof(InviteEnrollment, State, time.Time) (invite.SignedPermit, invite.Proof, error)
EnrollByInvite(context.Context, *http.Client, InviteEnrollment, *State) error
```

The parent mounts POST `/api/v1/invites/{id}/challenge` and `/claim`, with its
shared onboarding rate limit. Both callbacks resolve either Go `PathValue("id")`
or chi's `id` parameter. Challenge success and claim success return HTTP 200.
Not-yet-published approval returns 409. Invalid/replayed claims return 400 with
`{"code":"invalid_activation_claim","error":"invalid activation claim"}`.
Missing/consumed Redis challenges map to invalid claims; infrastructure failures
remain 503. All activation responses use `Cache-Control: no-store`.

The injected challenge contract matches HTTP's existing contract exactly:

```go
PutChallenge(context.Context, string, string, []byte, time.Duration) error
ConsumeChallenge(context.Context, string, string) ([]byte, error)
```

Use the parent Redis adapter; there is no local production challenge fallback.
Purpose is `activation-claim-v1`; lifetime is two minutes. Proofs sign canonical
CBOR of the typed challenge, prefixed by `go-tunnels/activation-claim/v1\x00`.
Version 1 binds network, invite, device, 32-byte nonce, and Unix expiry. Nonces and
64-byte signatures must use canonical unpadded base64url. The snapshot reader
only needs `Latest(context.Context) (snapshot.Envelope, error)`.

`InviteEnrollment` fields are `ControlURL`, `InviteLink`, `Code`, `DeviceID`,
`StatePath`, `RootPublicKey`, `NetworkID`, and `PollInterval`. The Linux helper
reuses and saves existing State keys before submission, consumes the fragment
locally, submits public proofs, polls the snapshot-gated challenge, and saves
the claimed credential atomically. A lost claim response causes a fresh challenge
and replacement credential. Context cancellation bounds polling. Parent command
and daemon wiring remains outside this package; these helpers do not transmit
private keys or the plaintext code. Root/network pins remain required.

## Outbox contract and migration

Every payload is the existing `devices.Event` shape: JSON `type`, `aggregate_id`,
and `occurred_at`. Approval emits `device.enrolled` and `invite.approved`; claims
emit `device.credential_claimed`. Existing device operations emit their existing
topics through the explicit transaction appender. No credential is in an event.
The parent's dispatcher owns stable outbox IDs and audit delivery.

`000011_active_device_credential.up.sql` creates the partial unique index
`device_credentials_one_active_per_device` for `revoked_at IS NULL`. Existing
duplicates cause migration failure without deleting or changing historical
credentials; explicit operator resolution is required before retrying. Only
migration 000011 belongs to this worker; 000010 is parent-owned.

## Worker edits

Paths below are relative to `/Users/s.okhrym/personal_code/go-tunnels`:

- `internal/control/devices/{service.go,service_test.go,memory_store.go,publication.go,publication_test.go,atomic_memory_test.go}`: required atomic enrollment port, explicit publication strategy, memory uniqueness without token loss, regression coverage.
- `internal/control/devices/storage/{repository.go,repository_test.go,activation.go}`: injected transaction event appender, transaction-bound identity creation/credential replacement, PostgreSQL tests.
- `internal/control/invites/{service.go,service_test.go,memory_store.go,approval_retry_test.go,submission.go,submission_retry_test.go}`: workflow delegation, public approval response, exact proof resubmission, replacement of obsolete credential-in-approval tests with workflow coverage.
- `internal/control/invites/storage/repository.go`: own-table-only persistence, exact retry semantics, transaction binding and invite row locking. Its existing test file received formatting only.
- `internal/control/services/storage/activation.go`: transaction-bound profile membership writer.
- `internal/app/control/workflows/{activation.go,activation_test.go,README.md}`: workflow ports, approval/claim use cases, signature/snapshot regression tests, this contract.
- `internal/app/control/storage/{activation.go,activation_test.go,credential_invariant_test.go,http_replay_test.go}`: use-case UoW, outbox appender, actual PostgreSQL/Redis envtests.
- `internal/control/httpapi/{activation.go,activation_test.go}`: standalone strict claim/challenge handlers and transport tests.
- `internal/node/{activation.go,activation_test.go}`: Linux proof/enrollment helper and existing-state tests.
- `internal/companion/{invites.go,invites_test.go,approval_retry_test.go}`: exact approval retry/response checks and standard WireGuard snapshot encoding.
- `migrations/000011_active_device_credential.{up,down}.sql`: unique active credential invariant.

No worker edits to server/router, identity, snapshots, coordination, relay,
app lifecycle, configuration, tooling, or other migrations. Existing parent
adapter moves/deletions are not worker changes. No commits, pushes, or worktrees.

## Verification and limits

The eleven scoped packages passed with actual PostgreSQL 17.6 and Redis 8.2,
including concurrent approval/claim, rollback at every write boundary, replay,
revocation, migration history preservation, and HTTP response loss followed by
node state persistence. Scoped race tests passed. Worker-owned package lint and
formatter checks passed. The companion WireGuard publication regression was
observed failing before its correction and rechecked afterwards.

All sidecar database tests use `TestPostgres*`, matching the parent's
`Integration|Postgres` selector:

- `TestPostgresApprovalRetriesExactDiffWithoutCredentialAndWritesOneOutboxPair`
- `TestPostgresApprovalRollsBackAllTablesAtEveryFailureBoundary`
- `TestPostgresClaimsRetryReplaceCredentialReplayAndConcurrentCredentials`
- `TestPostgresClaimOutboxFailureRollsBackCredentialReplacement`
- `TestPostgresHTTPResponseLossRequestsFreshChallengeAndPersistsReplacement`
- `TestPostgresMigrationRefusesDuplicatesWithoutDeletingCredentialHistory`
- `TestPostgresConcurrentApprovalProducesOneDeviceAndOneEventPair`
- `TestPostgresSharedChallengeIsConsumedOnceConcurrently`
- `TestPostgresClaimRotationAndRevocationUseConsistentLockOrder`
- `TestPostgresHTTPClaimReplayReturnsInvalidClaim400`

Required envtest inputs: `TEST_DATABASE_URL`, plus `TEST_REDIS_URL` for claim
tests. Sidecar envtests create isolated temporary PostgreSQL schemas and unique
Redis prefixes; neither production tables nor the Redis database are flushed.

This is module/HTTP verification, not deployed Linux networking E2E. During the
final broader check, concurrent parent work caused an undefined `NewWithBootstrap`
in `internal/app/node/bootstrap_test.go`, and
`control/coordination.TestHistoryRequiresExplicitDependency` failed with HTTP 200.
Broader lint also reported unchecked Close calls in parent node snapshot files
and formatting in parent HTTP snapshot/router files. Those files were untouched;
the parent must refresh the full suite after integrating its changes.
