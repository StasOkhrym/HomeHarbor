# Gateway enrollment

Bootstrap a gateway before publishing the first signed network snapshot. In the authenticated admin UI, issue a short-lived enrollment token with the **gateway** role. Keep the token private; the client invitation flow remains a separate companion-approved operation.

Run the finite command using the control origin and its independently trusted CA:

```sh
install -d -m 0700 state
go run ./cmd/agent enroll \
  --control https://control.example \
  --ca-file state/control-ca.pem \
  --state state/gateway.json \
  --name "Home gateway" > state/gateway-public.json
```

Enter the token at the hidden stdin prompt. For a deliberate scripted manual flow, redirect stdin from a private token file. The token has no command-line flag. The default control request deadline is 30 seconds; `--timeout` accepts a positive duration up to two minutes.

The command acquires the state lock, preserves or creates independent identity and WireGuard keys, verifies the enrolled gateway role and returned public keys, and atomically saves the credential. Stdout contains only `device_id`, `identity_public_key` and `wireguard_public_key`. Use those values in the initial snapshot manifest, including every gateway/device reference, and sign it with the trusted companion. Keep `gateway.json` private.

After a successful save, rerunning the same command returns the same public identity without another enrollment request or token prompt. Expired credentials do not prevent this local export. Existing state without a recorded gateway role is refused; it cannot be relabeled by this command. A process already using the state must stop before enrollment/export.

`agent enroll` finishes without starting tunnel, relay, coordination or forwarding. Start the ordinary `agent --config <gateway.toml>` runtime after supplying the signed network and appropriate peer configuration, using the same state path. The runtime owns its normal deny guard and credential recovery. Container networking and any sandbox isolation fence remain the container entrypoint's responsibility.

If a request fails, keep the generated state so its keys remain stable. No public success record is emitted until the credential is durably saved. If control consumed the token but the response/save failed, inspect the enrollment in the admin UI before retrying; a second token does not guarantee that an already registered identity can enroll again.
