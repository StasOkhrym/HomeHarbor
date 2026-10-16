# Admin panel

The English admin panel starts at `/admin/`. It manages your home network; the VPN client is a separate application. It calls application services directly through Chi
handlers; Go templates render typed view models. Self-hosted HTMX enhances
navigation, while mutations remain ordinary HTML forms.

## Read the three states separately

- **Saved:** catalog, profile, route approval or ACL metadata is in the control
  database. This does not authorize LAN traffic.
- **Signed / Published:** the trusted companion signed a network snapshot and
  control accepted it. The private signing key never enters the panel.
- **Reported runtime:** Connections shows the reporting device, its applied
  revision, available WireGuard counters, handshake observations and direct/relay
  path. These are reported facts, not service reachability checks. Missing reports
  and reports older than 90 seconds are unknown. A control outage does not mean
  the VPN stopped; a graceful stop is reported after owned cleanup.

Unavailable reads have an explicit error state, not an empty list or zero count.
Control failures can therefore be distinguished from an unconfigured network.

## Navigation and supported actions

The primary navigation has six destinations: Overview, Devices, Services,
Connections, Activity and Settings. Invitations are under Devices. Access,
Network, Security and the setup guide are under Settings; their existing URLs
continue to work. Appearance follows the device's light/dark preference.

| Screen      | Supported actions                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Overview    | Device/service counts, pending routes, service catalog; configuration details expand on demand                                    |
| Devices     | Registration details, public identities, confirmed credential revoke; Invitations contains signed invite status and legacy tokens |
| Services    | List and create web/native services, optional app and HTTPS health URLs                                                           |
| Connections | Latest per-device/runtime reports, source and freshness; optional device filter                                                   |
| Activity    | Historical audit events, dropdown filters, older history and live updates                                                         |
| Settings    | Access profiles/ACL preview, network routes/DNS, security and setup instructions                                                  |

Activity reads at most 200 committed audit rows at a time (100 by default).
Category, period and device dropdowns are always visible. More filters contains
specific action, result, administrator, target ID and row limit; active additional
filters keep that section open. Action and target ID filters use exact matches. A protected fragment refreshes
the recent window every four seconds while the tab is visible; failed reads
leave the last rows visible and mark the view stale. Reading older history or
opening an event holds the visible list in place and announces newly discovered
records. Event details show selected non-secret metadata, including the actor,
HTTP source IP, device/platform versions and subject names when available. Old
rows remain unknown where the original producer did not capture a fact.

Connections also refreshes every four seconds. Open details/focus stay in place
while current values update; additions wait for an explicit apply. A failed
refresh retains the rows but marks their current runtime state unknown. Each
reporter retains its own counters; gateway/client observations are not summed.
Older clients without telemetry keep working and show no self report. macOS
runtime reports currently omit privileged WireGuard statistics; the installed
helper is not silently replaced or granted broader access.

There is no edit/delete UI, global invite list, service health probe, passkey
management or recovery-code regeneration: those application operations are not
available. A configured health URL is displayed as **not checked**.

Forms assign a record ID before submission; Advanced allows an explicit bounded,
path-safe ID. A repeated service/profile submission conflicts rather than adding
another record. Route advertisements retain the existing repository semantics.
Validation retains allowed non-secret fields and never presents rejected input
as a successful save. Checkbox memberships preserve opaque IDs. Route actions
carry their exact target in the POST body, not a browser-normalized URL path.
Rejected URL userinfo is redacted; unparseable URLs are cleared rather than risk
echoing credentials.

## Review ACL changes before saving

Both editors use the existing default-deny compiler. The review page shows added,
removed and modified rules, plus full canonical before/after JSON in Advanced.
Only explicitly confirming that exact preview can replace the policy.

The confirmation MAC binds the canonical action and base revision to the
authenticated browser's session-bound CSRF token. It is not a companion signature.
The repository checks the base revision under the same lock used by API writers;
a stale or repeated confirmation returns a conflict without another revision.
Changing the preview payload or copying confirmation to another session is rejected.

## Credentials, recovery and companion

Login shows either first-passkey setup or the existing-account flow, based on
durable credential state. A failed state lookup never opens bootstrap. Recovery
codes are shown once after bootstrap and each code can be consumed only once.
If passkey persistence succeeds but recovery/session creation fails, setup reports
that the passkey was saved and directs the browser to reload and sign in. It does
not reopen registration or redeliver recovery plaintext. A lost successful
response also cannot be replayed to retrieve those codes; regeneration is not an
available feature.
Recovery entry stays disabled until JavaScript installs its submission handler;
the form has a POST fallback so a failed script cannot put codes in a URL.

Legacy enrollment tokens are a separate registration mechanism, not signed
invites. Their plaintext is shown only in the POST response, with `no-store`;
leaving the page clears the secret DOM. A browser-history restore goes to the
safe invites GET rather than repeating token issuance. Never put tokens, recovery
codes, passphrases or private keys in screenshots, URLs or logs.

Credential revoke blocks new control authentication, but does not remove an
already-issued signed LAN grant. The existing companion `revoke-device` command
publishes a client removal; it does not support arbitrary gateway/topology edits.
The panel explains this next step without executing the CLI or interpolating
user-controlled values into executable commands. Publication still requires
separate verification of gateway application.

## Local verification

Run `make dev-up`, then visit
`https://control.localhost:8443/admin/login`. If your browser does not trust the
local test CA, explicitly run `make dev-trust-ca` and follow the OS/browser trust
steps. Do not disable TLS verification. A person must complete the native passkey
registration/authentication prompts; handler tests do not replace that check.

Exercise service/profile creation, invalid forms, route approval/rejection, ACL
preview/confirmation, token display, device revoke and sign-out. Check keyboard
navigation, error announcements and the 390/1440 px layouts. Use only disposable
test records; do not revoke a real gateway for a UI smoke test.

Run `make verify` and `make integration` for the automated gates, plus
`node --test internal/web/assets/tests/browser.test.cjs` for the shipped
scripts' Activity, recovery and history-error behavior. These tests do not replace
visual or native passkey verification. SQL integration
includes concurrent confirmed policy replacements. Successful UI checks do not
prove the separate WireGuard, relay, DNS or network E2E milestone.
