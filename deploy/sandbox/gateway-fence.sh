#!/bin/sh
set -eu

test "$#" -eq 1
test -n "${SANDBOX_UNDERLAY_IP:-}"
test -n "${SANDBOX_PRIVATE_GATEWAY_IP:-}"
underlay=$(ip -o -4 addr show | awk -v address="$SANDBOX_UNDERLAY_IP/24" '$4 == address { print $2 }')
private=$(ip -o -4 addr show | awk -v address="$SANDBOX_PRIVATE_GATEWAY_IP/24" '$4 == address { print $2 }')
underlay=${underlay%%@*}
private=${private%%@*}
printf '%s\n' "$underlay" | grep -Eq '^(eth|ens)[0-9]+$' || {
    echo 'sandbox underlay interface not found' >&2
    exit 1
}
printf '%s\n' "$private" | grep -Eq '^(eth|ens)[0-9]+$' || {
    echo 'sandbox private interface not found' >&2
    exit 1
}
test "$underlay" != "$private"

# Independent of the product's wg0 ACL. A container on the underlay cannot
# bypass WireGuard by routing directly through this dual-homed gateway.
nft -f - <<EOF
table inet homeharbor_sandbox_fence {
  chain forward {
    type filter hook forward priority -200; policy accept;
    iifname "$underlay" oifname "$private" drop
  }
}
EOF

exec /agent --config "$1"
