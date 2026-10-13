//go:build darwin || linux

package macos

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

// RunSystemHelper is the only production entrypoint to privileged native
// operations. Paths and binaries are fixed; caller stdin carries signed desired
// state and the private device key, never executable or persistence paths.
func RunSystemHelper(ctx context.Context, input io.Reader) error {
	if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
		return errors.New("network-helper requires an explicitly installed macOS root helper")
	}

	callerUID, err := systemHelperCaller(os.Geteuid(), os.Getenv("SUDO_UID"))
	if err != nil {
		return err
	}

	executable, err := os.Executable()
	if err != nil || executable != InstalledClientPath {
		return errors.New("network-helper must run from the fixed root-owned installed client")
	}

	if err := validateNativeExecutable(InstalledClientPath, "/", 0); err != nil {
		return err
	}

	info, err := os.Lstat(SystemPolicyPath)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || stat.Uid != 0 {
		return ErrOwnershipConflict
	}

	policy, err := LoadHelperPolicy(SystemPolicyPath, SystemJournalPath)
	if err != nil {
		return err
	}
	if callerUID != policy.OwnerUID {
		return errors.New("network-helper caller differs from provisioned owner")
	}

	ops, err := newNativeOperations(policy, nativeSettings{
		binaryPath: InstalledWireGuardPath, wgPath: InstalledWGPath,
		binaryRoot: "/", socketDir: "/var/run/wireguard",
		resolverDir: "/etc/resolver", ownerUID: 0,
	}, systemTunnelDriver{wgPath: InstalledWGPath}, nativeCommandRunner{})
	if err != nil {
		return err
	}

	operation, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if closer, ok := input.(io.Closer); ok {
		stop := context.AfterFunc(operation, func() { _ = closer.Close() })
		defer stop()
	}

	return ExecuteHelper(operation, input, policy, callerUID, ops)
}

func systemHelperCaller(euid int, sudoUID string) (int, error) {
	uid, err := strconv.Atoi(sudoUID)
	if euid != 0 || err != nil || uid <= 0 || uid > 1<<31-1 || strconv.Itoa(uid) != sudoUID {
		return 0, errors.New("network-helper requires the provisioned user to invoke sudo")
	}

	return uid, nil
}
