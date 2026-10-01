#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
command -v limactl >/dev/null 2>&1 || {
    echo 'limactl is required; install Lima before starting the Linux test VM' >&2
    exit 2
}
instance=${LIMA_INSTANCE:-go-tunnels-acceptance}
case "$instance" in '' | *[!a-zA-Z0-9_-]*)
    echo 'Invalid LIMA_INSTANCE' >&2
    exit 2
    ;;
esac
if limactl list --format '{{.Name}}' | grep -Fxq "$instance"; then
    # Never reuse a VM exposing unrelated host files. A fresh instance is safer
    # than silently stopping/editing a VM another local workflow may own.
    limactl list --json "$instance" | python3 -c '
import json, sys
config = json.load(sys.stdin)["config"]
mounts = config.get("mounts", [])
if len(mounts) != 1 or mounts[0]["location"] != sys.argv[1] or mounts[0].get("writable", False):
    sys.exit("Unsafe VM mounts; select a fresh LIMA_INSTANCE for isolated acceptance")
' "$(pwd)"
    limactl start --tty=false "$instance"
else
    limactl start --name "$instance" --tty=false --mount-only "$(pwd)" deploy/lima/ubuntu.yaml
fi
