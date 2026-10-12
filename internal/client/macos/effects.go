package macos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
)

const (
	darwinIfconfig = "/sbin/ifconfig"
	darwinRoute    = "/sbin/route"
)

// effectRunner takes a fixed executable and a discrete argument vector. No
// shell, PATH lookup, or caller-selected executable is involved in host effects.
type effectRunner interface {
	Run(context.Context, string, ...string) (string, error)
}

type nativeCommandRunner struct{}

func (nativeCommandRunner) Run(ctx context.Context, path string, args ...string) (string, error) {
	if path != darwinIfconfig && path != darwinRoute {
		return "", errors.New("unsupported native executable")
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("native %s operation failed: %w (%s)",
			filepath.Base(path), err, strings.TrimSpace(string(output[:min(len(output), 4096)])))
	}
	return string(output), nil
}

// darwinEffects owns only bounded address, route, and scoped resolver effects.
// The tunnel process and signed snapshot transaction remain separate owners.
type darwinEffects struct {
	authority   Authority
	resolverDir string
	marker      string
	runner      effectRunner
}

func newDarwinEffects(
	authority Authority,
	resolverDir string,
	runner effectRunner,
) (*darwinEffects, error) {
	if authority.NetworkID == "" || authority.DeviceID == "" ||
		len(authority.Root) != 32 || !validNativeBounds(authority.Bounds) ||
		!filepath.IsAbs(resolverDir) || runner == nil {
		return nil, errors.New("native effects require provisioned authority and runner")
	}

	digest := sha256.New()
	digest.Write(authority.Root)
	digest.Write([]byte{0})
	digest.Write([]byte(authority.NetworkID))
	digest.Write([]byte{0})
	digest.Write([]byte(authority.DeviceID))
	return &darwinEffects{
		authority: authority, resolverDir: resolverDir,
		marker: hex.EncodeToString(digest.Sum(nil)), runner: runner,
	}, nil
}

func (e *darwinEffects) Address(ctx context.Context, name string, address netip.Prefix) error {
	if !utunName.MatchString(name) || !e.overlayAddress(address) {
		return errors.New("native overlay address or interface is outside provisioned scope")
	}

	if _, err := e.runner.Run(ctx, darwinIfconfig, name, "inet", address.String(),
		address.Addr().String(), "alias"); err != nil {
		return err
	}

	_, err := e.runner.Run(ctx, darwinIfconfig, name, "up")

	return err
}

func (e *darwinEffects) AddRoute(ctx context.Context, name string, route netip.Prefix) error {
	if !utunName.MatchString(name) || !e.privateRoute(route) {
		return errors.New("native route or interface is outside provisioned scope")
	}

	_, err := e.runner.Run(ctx, darwinRoute,
		"-q", "-n", "add", "-inet", route.String(), "-interface", name)

	return err
}

func (e *darwinEffects) RemoveRoute(ctx context.Context, name string, route netip.Prefix) error {
	if !utunName.MatchString(name) || !e.privateRoute(route) {
		return errors.New("native route or interface is outside provisioned scope")
	}

	output, err := e.runner.Run(ctx, darwinRoute, "-n", "get", "-inet", route.String())
	if err != nil {
		return fmt.Errorf("inspect native route before cleanup: %w", err)
	}

	actual, device, err := parseDarwinRoute(output)
	if err != nil {
		return err
	}
	if actual != route {
		return nil // route get selected a broader route; our exact route is absent.
	}
	if device != name {
		return ErrOwnershipConflict
	}

	_, err = e.runner.Run(ctx, darwinRoute, "-q", "-n", "delete", "-inet", route.String())

	return err
}

func (e *darwinEffects) SetDNS(_ context.Context, resolver networkplan.Resolver) error {
	if !e.resolverAllowed(resolver) {
		return errors.New("native resolver is outside provisioned scope")
	}

	if err := e.checkResolverDir(); err != nil {
		return err
	}

	path := filepath.Join(e.resolverDir, resolver.Suffix)
	content := e.resolverContent(resolver)
	if _, err := os.Lstat(path); err == nil {
		if err := e.compareResolver(path, content); err != nil {
			return err
		}

		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create scoped resolver: %w", err)
	}

	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()

	if _, err := file.Write(content); err != nil {
		return err
	}

	if err := file.Sync(); err != nil {
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	failed = false

	return syncDirectory(e.resolverDir)
}

func (e *darwinEffects) RemoveDNS(_ context.Context, resolver networkplan.Resolver) error {
	if !e.resolverAllowed(resolver) {
		return errors.New("native resolver is outside provisioned scope")
	}

	if err := e.checkResolverDir(); err != nil {
		return err
	}

	path := filepath.Join(e.resolverDir, resolver.Suffix)
	if err := e.compareResolver(path, e.resolverContent(resolver)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	if err := os.Remove(path); err != nil {
		return err
	}

	return syncDirectory(e.resolverDir)
}

func (e *darwinEffects) overlayAddress(address netip.Prefix) bool {
	scope := e.authority.Bounds.Overlay
	return address.IsValid() && address.Addr().Is4() && address.Bits() == 32 &&
		scope.Contains(address.Addr())
}

func (e *darwinEffects) privateRoute(route netip.Prefix) bool {
	scope := e.authority.Bounds.Private
	return route.IsValid() && route.Addr().Is4() && route.Bits() >= scope.Bits() &&
		route.Bits() > 0 && route == route.Masked() && scope.Contains(route.Addr())
}

func (e *darwinEffects) resolverAllowed(resolver networkplan.Resolver) bool {
	return resolver.Suffix == e.authority.Bounds.Suffix && resolver.Address.Is4() &&
		e.authority.Bounds.Private.Contains(resolver.Address)
}

func (e *darwinEffects) resolverContent(resolver networkplan.Resolver) []byte {
	return []byte("# HomeHarbor owner " + e.marker + "\n" +
		"domain " + resolver.Suffix + "\n" +
		"nameserver " + resolver.Address.String() + "\n")
}

func (e *darwinEffects) checkResolverDir() error {
	info, err := os.Lstat(e.resolverDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(e.resolverDir, 0o755); err != nil {
			return err
		}

		info, err = os.Lstat(e.resolverDir)
	}

	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0o022 != 0 ||
		stat.Uid != uint32(os.Geteuid()) {
		return ErrOwnershipConflict
	}

	return nil
}

func (e *darwinEffects) compareResolver(path string, expected []byte) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) {
		return ErrOwnershipConflict
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(content, expected) {
		return ErrOwnershipConflict
	}

	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()

	return dir.Sync()
}

func parseDarwinRoute(output string) (netip.Prefix, string, error) {
	fields := map[string]string{}
	for line := range strings.SplitSeq(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		if key != "destination" && key != "mask" && key != "interface" {
			continue
		}

		if _, exists := fields[key]; exists {
			return netip.Prefix{}, "", errors.New("ambiguous native route lookup")
		}

		fields[key] = strings.TrimSpace(value)
	}

	if fields["destination"] == "default" {
		return netip.Prefix{}, fields["interface"], nil
	}

	addr, err := netip.ParseAddr(fields["destination"])
	if err != nil || !addr.Is4() || fields["interface"] == "" {
		return netip.Prefix{}, "", errors.New("invalid native route lookup")
	}

	bits := 32
	if mask := fields["mask"]; mask != "" {
		var parsed net.IPMask
		if strings.HasPrefix(mask, "0x") || strings.HasPrefix(mask, "0X") {
			value, parseErr := strconv.ParseUint(mask[2:], 16, 32)
			if parseErr != nil {
				return netip.Prefix{}, "", errors.New("invalid native route mask")
			}

			parsed = net.IPMask{
				byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
			}
		} else {
			parsed = net.IPMask(net.ParseIP(mask).To4())
		}

		maskBits, total := parsed.Size()
		if total != 32 {
			return netip.Prefix{}, "", errors.New("non-contiguous native route mask")
		}

		bits = maskBits
	}

	return netip.PrefixFrom(addr, bits).Masked(), fields["interface"], nil
}
