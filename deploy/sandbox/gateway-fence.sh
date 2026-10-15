#!/bin/sh
set -eu

test "$#" -gt 0
case "$1" in
enroll | identity) ;;
*) test "$#" -eq 1 ;;
esac

test -n "${SANDBOX_UNDERLAY_IP:-}"
test -n "${SANDBOX_PRIVATE_GATEWAY_IP:-}"

for subnet in "${SANDBOX_OVERLAY_SUBNET:-}" "${SANDBOX_PRIVATE_SUBNET:-}"; do
    case "$subnet" in
    *[!0-9./]*)
        echo 'sandbox subnet contains invalid characters' >&2
        exit 1
        ;;
    esac
    printf '%s\n' "$subnet" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}/24$' || {
        echo 'sandbox requires bounded IPv4 /24 subnets' >&2
        exit 1
    }
done

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
# Docker internal bridges reject overlay source addresses. Translate only
# tunnel traffic already admitted by the product's forward ACL; do not alter
# host Docker rules or expose the fixtures on the underlay.
table ip homeharbor_sandbox_egress {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "wg0" oifname "$private" ip saddr $SANDBOX_OVERLAY_SUBNET ip daddr $SANDBOX_PRIVATE_SUBNET snat to $SANDBOX_PRIVATE_GATEWAY_IP
  }
}
EOF

case "$1" in
enroll | identity) exec /agent "$@" ;;
*) exec /agent --config "$1" ;;
esac
