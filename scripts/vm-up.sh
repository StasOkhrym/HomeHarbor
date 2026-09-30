#!/bin/sh
set -eu

command -v limactl >/dev/null 2>&1 || {
    echo "limactl is required; install Lima before starting the Linux test VM" >&2
    exit 1
}
if limactl list --format '{{.Name}} {{.Status}}' | grep -q '^go-tunnels-vm '; then
    # Reusing the named instance preserves its installed kernel tools and
    # avoids treating a stopped developer VM as a provisioning failure.
    limactl start --tty=false go-tunnels-vm
else
    limactl start --name go-tunnels-vm --tty=false deploy/lima/ubuntu.yaml
fi
