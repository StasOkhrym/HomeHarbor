#!/bin/sh
set -eu

command -v limactl >/dev/null 2>&1 || {
    echo "limactl is required; install Lima before starting the Linux test VM" >&2
    exit 1
}
limactl start --name go-tunnels-vm --tty=false deploy/lima/ubuntu.yaml
