#!/bin/sh
set -eu

command -v limactl >/dev/null 2>&1 || exit 0
limactl stop go-tunnels-vm || true
