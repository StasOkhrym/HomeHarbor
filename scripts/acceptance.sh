#!/bin/sh
set -eu

# This part is portable and proves both the production relay composition and
# the node bridge vertical slice. The Linux-only checks below add kernel
# interfaces, nftables, and namespaces.
go test ./internal/app/relay -run '^TestRelayAppBridgesTwoNodesThroughProductionListeners$' -count=1
go test ./internal/node -run '^TestRelayOnlyNodeBridgesForwardOpaqueUDPInBothDirections$' -count=1

run_lima_namespace_acceptance() {
    command -v limactl >/dev/null 2>&1 || {
        echo "acceptance requires Linux; install Lima and run make vm-up first" >&2
        exit 2
    }

    instance=${LIMA_INSTANCE:-go-tunnels-vm}
    limactl shell "$instance" true >/dev/null 2>&1 || {
        echo "Lima instance $instance is not running; run make vm-up first" >&2
        exit 2
    }

    vm_arch=$(limactl shell "$instance" uname -m)
    case "$vm_arch" in
        x86_64) go_arch=amd64 ;;
        aarch64|arm64) go_arch=arm64 ;;
        *)
            echo "unsupported Lima architecture: $vm_arch" >&2
            exit 2
            ;;
    esac

    binary=".local/acceptance-linux-$go_arch.test"
    GOOS=linux GOARCH="$go_arch" go test -c ./internal/acceptance -o "$binary"
    repo_path=$(pwd)
    # Namespace creation, nftables, and WireGuard device setup require
    # CAP_NET_ADMIN. Lima's default user intentionally has no such capability,
    # so the VM harness elevates only this disposable test process.
    limactl shell "$instance" sudo -- "$repo_path/$binary" -test.run='^TestLinuxNamespace.*$' -test.count=1 -test.v
    exit 0
}

if [ "$(uname -s)" != "Linux" ]; then
    run_lima_namespace_acceptance
fi
for command_name in ip nft curl python3; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "$command_name is required for network acceptance" >&2
        exit 2
    }
done

go test ./internal/acceptance -run '^TestLinuxNamespace.*$' -count=1 -v
