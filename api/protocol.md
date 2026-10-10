# HomeHarbor protocol

## Relay transport

Control advertises the exact `wss://<relay-host>/relay/udp` endpoint and the
`udp_pair` capability. The old `/relay/udp/v2` route and `udp_pair_v2` capability
are rejected. Peer-bound relay tickets retain their signed payload schema:
`v=1`, `aud=relay`, `jti`, `sid`, `did`, `dst`, and `exp`. The endpoint and
capability are not embedded in those signed bytes.

After authenticated WSS admission, the relay offers a dynamic UDP address and
nonce. The client probes it with `HHUP` plus the 43-character nonce; the relay
returns `HHUC` plus the 43-character challenge. The client confirms that
challenge over WSS before opaque WireGuard datagrams may flow. A static relay
UDP address is neither configured nor returned by control. Old clients must be
updated together with the relay because the probe framing has changed.

## Credential leases

All endpoints use JSON under `/api/v1`. Plaintext credential responses carry
`Cache-Control: no-store`. Credentials expire at their issuance timestamp plus
at most 15 minutes; clients persist the returned expiry and never infer it from
startup or device creation. Zero expiry in old local state means unknown.

- `POST /devices/credentials/challenge`: `{ "device_id": "..." }`; returns
  `CredentialChallenge` with `version` (1), `network_id`, `device_id`, `nonce`
  (32 random bytes, unpadded canonical base64url), `expires_at` (Unix seconds).
  Lifetime is 60 seconds. Plausible IDs receive the same response without a
  device lookup. Shared, fail-closed onboarding limits apply.
- `POST /devices/credentials/recovery`: `CredentialProof` contains `challenge`
  and `signature` (64 Ed25519 bytes, canonical unpadded base64url).
  The signed bytes are ASCII `homeharbor/credential-recovery/v1` followed by
  one NUL byte followed by canonical CBOR of the five challenge fields with
  their JSON names as CBOR text keys. No JSON serialization is signed.
- Recovery returns `CredentialLease`: `device_id`, `credential`, `expires_at`
  (RFC3339 UTC). Rotation at `POST /devices/credentials/rotate` returns the same
  lease, authenticating the current bearer credential.
- Enrollment preserves its device fields and includes `credential_expires_at`.
  Invite claim preserves its `device` envelope and includes that same field.

Recovery checks network, version, nonce and expiry, verifies against the
registered identity, atomically consumes the dedicated shared Redis challenge,
then locks the SQL device row and rechecks active status and the verified
identity. Credential revocation, replacement and the non-secret outbox fact
commit together. Missing, revoked, wrong-key and invalid proofs return the same
public invalid-proof error. A consumed nonce cannot be retried; loss of a
successful response is recovered with a fresh challenge and the same identity.
Old bearer credentials have no overlap. Recovery never enrolls a device.
