#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
    echo "acceptance requires the Linux Lima VM (TUN, nftables, and network namespaces)" >&2
    exit 2
fi
for command_name in ip nft; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "$command_name is required for network acceptance" >&2
        exit 2
    }
done

echo "Linux network prerequisites are present; namespace acceptance scenarios are not wired yet" >&2
exit 2
