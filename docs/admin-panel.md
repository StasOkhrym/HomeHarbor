# Admin panel

The English admin panel starts at `/admin/`. It manages your home network; the VPN client is a separate application. It calls application services directly through Chi
handlers; Go templates render typed view models. Self-hosted HTMX enhances
navigation. Network changes use ordinary HTML forms; account security and
administration use same-origin JSON with session-bound CSRF protection. Their
controls remain disabled until JavaScript is ready.

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
Network, Security, Administrators, Email and the setup guide are under Settings; their existing URLs
continue to work. Appearance follows the device's light/dark preference.

| Screen      | Supported actions                                                                                                                 |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Overview    | Device/service counts, pending routes, service catalog; configuration details expand on demand                                    |
| Devices     | Registration details, public identities, confirmed credential revoke; Invitations contains signed invite status and legacy tokens |
| Services    | List and create web/native services, optional app and HTTPS health URLs                                                           |
| Connections | Latest per-device/runtime reports, source and freshness; optional device filter                                                   |
| Activity    | Historical audit events, dropdown filters, older history and live updates                                                         |
| Settings    | Access profiles/ACL preview, network routes/DNS, personal security, owner administration/email and setup instructions             |

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

There is no general catalog edit/delete UI, global device-invite list or service
health probe. A configured health URL is displayed as **not checked**.

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

The first owner creates a passkey and then configures an email address and password.
Existing legacy owner passkeys keep their user handle; their restricted setup
session cannot administer the network. Configuring the password ends those old
sessions. Subsequent sign-in requires email and password, followed by a passkey,
an authenticator code, or a one-use recovery code. There is no public registration.
A failed authority lookup never opens bootstrap or grants access.

Security shows the current sign-in method/time, saved passkeys, authenticator,
email confirmation and remaining recovery-code count. Recent sign-in is required
for changes. Adding/removing a method or choosing **Sign out all devices** ends
all this account's sessions and invalidates pending epoch-bound sign-in/account
links across replicas. Signing out all devices preserves the password, factors
and recovery codes; it does not list or remove individual remote devices.
Regenerating recovery codes replaces the old set and displays the new set once.
Keep these values private: neither refresh nor replay can recover them.

Only the owner can view Administrators, invite another administrator, revoke an
invited administrator, or use Email settings. The owner cannot revoke their own
account. Invitations require password setup and a first verification method;
setup grants no admin session, so a fresh normal sign-in is required afterward.
An already active or revoked address cannot be silently reinvited. Revocation
ends that administrator's access through live SQL authority.

Account email uses optional authenticated TLS SMTP. A provider such as Mailgun is
optional; any configured compatible SMTP server can submit invitations,
confirmation/reset links and security notices. Email is not a sign-in OTP.
Settings shows configured capability and durable last-test state; the test sends
only to the verified owner's address. Queued means scheduled; sent means SMTP
acceptance, not inbox delivery. SMTP is not a readiness or VPN dependency.

Account controls require JavaScript and display explicit confirmations for
sensitive actions. Secret-bearing responses have `no-store`; leaving the page
clears displayed secrets. Failed or ambiguous requests never display raw provider
responses. Native passkey prompts still require the person using the device.

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
