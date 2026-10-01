#!/bin/sh
set -eu
cd "$(dirname "$0")/.."

if [ "$(uname -s)" = Linux ]; then
    test "$(id -u)" -eq 0 || {
        echo 'Linux acceptance requires root in a disposable VM' >&2
        exit 2
    }
    for name in go ip nft wg curl python3 systemctl resolvectl; do
        command -v "$name" >/dev/null 2>&1 || {
            echo "$name is required for network acceptance" >&2
            exit 2
        }
    done
    systemctl is-active --quiet systemd-resolved || {
        echo 'Real systemd-resolved must be running' >&2
        exit 2
    }
else
    command -v limactl >/dev/null 2>&1 || {
        echo 'Linux acceptance requires Lima' >&2
        exit 2
    }
fi

go test ./internal/app/relay -run '^TestRelayAppBridgesTwoNodesThroughProductionListeners$' -count=1
go test ./internal/node -run '^TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections$' -count=1
pattern='^TestLinux(Namespace|Resolved).*$'
if [ "$(uname -s)" = Linux ]; then
    go test -tags=network_acceptance ./internal/acceptance -run "$pattern" -count=1 -v
else
    instance=${LIMA_INSTANCE:-go-tunnels-acceptance}
    LIMA_INSTANCE="$instance" sh scripts/vm-up.sh
    vm_arch=$(limactl shell "$instance" uname -m)
    case "$vm_arch" in
    x86_64) go_arch=amd64 ;;
    aarch64 | arm64) go_arch=arm64 ;;
    *)
        echo "Unsupported Lima architecture: $vm_arch" >&2
        exit 2
        ;;
    esac
    mkdir -p .local
    binary=".local/acceptance-linux-$go_arch.test"
    GOOS=linux GOARCH="$go_arch" go test -tags=network_acceptance -c ./internal/acceptance -o "$binary"
    limactl shell "$instance" sudo -- "$(pwd)/$binary" -test.run="$pattern" -test.count=1 -test.v
fi
