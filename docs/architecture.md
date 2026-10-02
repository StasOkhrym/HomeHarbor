# Architecture

HomeHarbor is a modular monolith for coordination and administration, with a
separate encrypted relay and Linux nodes. It is still under development: the
full signed-onboarding-to-LAN sandbox is not yet verified end to end.

## Processes and ownership

`control` owns HTTPS APIs, browser authentication, coordination and durable
metadata. `relay` forwards opaque WireGuard datagrams; it does not decrypt LAN
traffic. `agent` is the home gateway and `client` is the remote Linux endpoint.
`admin` is the trusted companion that signs network changes locally. `migrate`
owns schema upgrades and serializes them using a database advisory lock.

Entrypoints load flags/config and signals. Application packages assemble explicit
dependencies and supervise `Component.Run(context.Context) error` workers. A
worker failure cancels sibling workers and shutdown waits for their completion;
an invalid trust configuration is rejected before creating identity or tunnels.
Gateway/client wiring lives in `internal/app/node`, not duplicated in `cmd`.

Docker packages these processes; it does not replace the operating system.
TUN/WireGuard, routing and nftables require a Linux kernel. Mac Compose is for
backend/UI development. Linux namespaces and Lima exercise privileged network
operations without modifying the Mac's home-network forwarding.

## Module boundaries

Identity, devices, routes, policy, services, invites, snapshots, coordination and
audit are vertical modules. Consumers declare small interfaces for the operations
they actually need. There is no universal CRUD repository or god-service.

Module `storage.Repository` adapters implement durable ports using PostgreSQL.
The domain does not import pgx, Redis, Chi or HTTP. Neutral names separate domain
contracts from adapters; they do not promise automatic SQL portability. TOML
therefore truthfully selects `database.driver = "postgres"`.

Cross-module enrollment/activation workflows share one SQL transaction. Each
adapter writes only its own tables. Outbox events commit with durable changes;
delivery is at least once, so consumers must be idempotent. Watermill GoChannel
carries local events, not the primary synchronous transaction.

## Storage authority

The DB owns devices, credentials, recovery-code hashes, invite lockout, profiles,
signed snapshots, audit and outbox. Redis owns short-lived challenges, encrypted
WebAuthn ceremonies, browser sessions and distributed auth/onboarding quotas.
Redis uses TTL, atomic consumption/revoke and hashed identifiers. Browser sessions
have no SQL fallback; moving them invalidates pre-existing SQL sessions.

Redis failure makes dependent authentication/onboarding unavailable (`503`), not
unauthenticated (`401`) and not silently successful. Established tunnels and
DB-backed device credential rotation remain independent of Redis. Private keys,
active sockets, goroutines and UDP endpoint bindings belong to their local owners,
not to a distributed cache.

## Trust and networking

The companion's encrypted root key stays local. Control stores the public key
and signed snapshots, but cannot manufacture a trusted LAN-access grant. Nodes
verify canonical signed snapshot chains, revisions and previous hashes. Last
valid state survives a control outage; rollback/gaps/tampering are rejected.

Gateway ACL is default-deny and scoped to tunnel traffic. Preparation validates a
whole update before changes; a tunnel-only deny guard covers runtime application.
A partial failure stays fail-closed, never claims a mixed revision is applied.
Unrelated host forwarding must not be changed by tunnel policy.

Relay v2 reserves peer-pair UDP ingress through authenticated WSS. Endpoint binding
requires reachability proof and authenticated confirmation. Datagrams do not
contain bearer tickets. Rebinding requires authentication; ticket expiry alone
does not tear down an already established active session during control outage.

## HTTP and TLS

Chi composes standard `net/http` handlers in resource groups. Handlers receive
application services explicitly; they do not discover capabilities through
runtime type assertions or call other modules through internal HTTP.

Traefik terminates browser HTTPS/WSS and authenticates relay-backend TLS using
both CA and server name. It has no Docker socket, dashboard or network-admin
capability. Relay UDP is not an HTTP proxy path. TLS certificates and the
companion signing root are separate trust authorities.

Local development uses a test CA and loopback port 8443. Public certificate
automation and VPS deployment are deferred; no production rollout is provided.
The control plane never receives DNS-provider credentials or TLS CA private keys.

## Readability and verification

Gofumpt, gci and goimports establish one style; golines targets 100 columns and
expands long expressions/struct literals vertically. Keep multi-field runtime
configuration literals one field per line. Do not split protocol strings or SQL
solely to satisfy a line-width target. Comments explain trust, transaction
boundaries, ownership, replay protection and partial failures, not obvious syntax.

`make verify` checks formatting without edits, correctness lint (including vet),
tooling tests, the full Go race suite and command builds. The import-boundary test
runs once as part of that suite. DB/Redis contracts and Linux network acceptance
remain separate heavier commands. Passing these component tests does not mean
the full signed-onboarding/data-path milestone is complete.

## Operational settings and constants

`[runtime]` is startup-only TOML: HTTP/shutdown, Redis operation timeout,
auth/onboarding quotas, challenge/credential lifetimes and relay admission bounds.
It is decoded over role defaults before validation: omission keeps the default;
explicit zero is invalid. Restart the process after changing it. Domain consumers
receive typed durations through their own options, not the runtime config package.

Login/recovery defaults to 5 requests/minute/IP, onboarding to 10. Operators can
raise these to 30 and 60 respectively; control warns above defaults. These ceilings
are conservative operational bounds, not a security-audit guarantee. Invite code
lockout remains 5 failed attempts in the DB, independent of per-IP Redis quotas.

Claim TTL is 1s..2m and credential TTL is 1m..15m. Shorter credentials affect both
enrollment and rotation; clients must rotate within the configured lifetime.
Automatic supervised node credential renewal is not proven by these config tests.
Redis failures still deny new protected operations; quotas never fall back locally.

Signature domains, supported schema/protocol versions, key/signature lengths,
maximum UDP payload size and snapshot-chain checks are named trust constants, not
operator knobs. Container secret paths and runtime UID are deployment contracts.
Loopback ports are configurable local defaults; sample CIDRs and dummy markers are
fixtures, not assumptions about the operator's LAN.

## Product namespace

The product is HomeHarbor and its Go module is `github.com/StasOkhrym/homeharbor`.
Configuration overrides use `HOMEHARBOR_*`; container mounts use `/etc/homeharbor`.
Cookies, Redis namespaces, database identity and nftables ownership use the same
product namespace. Snapshot/invite/claim signatures use `homeharbor/...` domains;
relay binding messages use `HHU2`. There are no previous-product aliases.

This is a deliberate breaking rename of a local experiment, not a rolling
upgrade. Old signed state and credentials are not claimed compatible. Local
state setup is separate from source renaming; do not mix old nodes with the new
control/relay. Deferred native clients must adopt the matching contracts when
their development resumes. Fixture CIDRs never authorize a real LAN by default.
