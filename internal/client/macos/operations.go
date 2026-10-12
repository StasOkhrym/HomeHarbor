//go:build darwin || linux

package macos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/tunnel"
)

type tunnelDriver interface {
	Launch(context.Context, string, string) error
	Configure(context.Context, string, wgtypes.Config) error
	Device(context.Context, string) (*wgtypes.Device, error)
}

type nativeSettings struct {
	binaryPath  string
	wgPath      string
	binaryRoot  string
	socketDir   string
	resolverDir string
	ownerUID    int
}

type nativeOperations struct {
	*darwinEffects
	policy   HelperPolicy
	settings nativeSettings
	driver   tunnelDriver
	pinned   wgtypes.Key
	relay    wgtypes.Key
}

type tunnelOwnership struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Device    uint64 `json:"socket_device"`
	Inode     uint64 `json:"socket_inode"`
}

func newNativeOperations(
	policy HelperPolicy,
	settings nativeSettings,
	driver tunnelDriver,
	runner effectRunner,
) (*nativeOperations, error) {
	pinned, err := wgtypes.ParseKey(policy.LocalWireGuardPublicKey)

	relay, relayErr := wgtypes.ParseKey(policy.RelayPeerPublicKey)
	if err != nil || pinned == (wgtypes.Key{}) || driver == nil ||
		relayErr != nil || relay == (wgtypes.Key{}) || relay == pinned ||
		!filepath.IsAbs(policy.JournalPath) || !filepath.IsAbs(settings.binaryPath) ||
		!filepath.IsAbs(settings.wgPath) ||
		!filepath.IsAbs(settings.binaryRoot) || !filepath.IsAbs(settings.socketDir) ||
		settings.ownerUID < 0 || !validTunnelScope(policy.Tunnel) {
		return nil, errors.New("native tunnel requires provisioned identity and fixed paths")
	}

	if err := errors.Join(
		validateNativeExecutable(settings.binaryPath, settings.binaryRoot, settings.ownerUID),
		validateNativeExecutable(settings.wgPath, settings.binaryRoot, settings.ownerUID),
	); err != nil {
		return nil, err
	}

	effects, err := newDarwinEffects(policy.Authority, settings.resolverDir, runner)
	if err != nil {
		return nil, err
	}

	return &nativeOperations{
		darwinEffects: effects,
		policy:        policy,
		settings:      settings,
		driver:        driver,
		pinned:        pinned,
		relay:         relay,
	}, nil
}

func (o *nativeOperations) Prepare(ctx context.Context, plan networkplan.Plan) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := o.validatePeers(plan); err != nil {
		return err
	}

	return errors.Join(
		validateNativeExecutable(o.settings.binaryPath, o.settings.binaryRoot, o.settings.ownerUID),
		validateNativeExecutable(o.settings.wgPath, o.settings.binaryRoot, o.settings.ownerUID),
	)
}

func (o *nativeOperations) Create(ctx context.Context, journalPath string) (string, error) {
	if journalPath != o.policy.JournalPath {
		return "", errors.New("native tunnel journal differs from provisioning")
	}

	if err := validateNativeExecutable(
		o.settings.binaryPath,
		o.settings.binaryRoot,
		o.settings.ownerUID,
	); err != nil {
		return "", err
	}

	for _, path := range []string{o.namePath(), o.markerPath()} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return "", errors.Join(ErrOwnershipConflict, err)
		}
	}

	if err := o.driver.Launch(ctx, o.settings.binaryPath, o.namePath()); err != nil {
		return "", err
	}

	return o.ResolveCreated(ctx, journalPath)
}

func (o *nativeOperations) ResolveCreated(ctx context.Context, journalPath string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if journalPath != o.policy.JournalPath {
		return "", errors.New("native tunnel recovery journal differs from provisioning")
	}

	name, err := o.readName()
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Lstat(o.markerPath()); errors.Is(markerErr, os.ErrNotExist) {
			return "", nil
		}

		return "", ErrOwnershipConflict
	}
	if err != nil {
		return "", err
	}

	marker, err := o.readMarker()
	if errors.Is(err, os.ErrNotExist) {
		marker, err = o.captureOwnership(ctx, name)
		if errors.Is(err, os.ErrNotExist) {
			// wireguard-go writes its name before opening UAPI. A failed
			// startup can leave the private name without a live daemon.
			if err := os.Remove(o.namePath()); err != nil {
				return "", err
			}

			return "", syncDirectory(filepath.Dir(o.policy.JournalPath))
		}

		if err == nil {
			err = o.saveMarker(marker)
		}
	}

	if err != nil {
		return "", err
	}
	if marker.Name != name {
		return "", ErrOwnershipConflict
	}

	if _, err := o.verifySocket(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	return name, nil
}

func (o *nativeOperations) Configure(
	ctx context.Context,
	name string,
	plan networkplan.Plan,
	config TunnelConfig,
) error {
	if _, err := o.ownedTunnel(ctx, name, false); err != nil {
		return err
	}

	private, err := wgtypes.ParseKey(config.PrivateKey)
	if err != nil || private.PublicKey() != o.pinned ||
		config.BridgeEndpoint != o.policy.Tunnel.BridgeEndpoint ||
		config.ListenPort != o.policy.Tunnel.ListenPort {
		return errors.New("native configuration differs from provisioned identity or bridge")
	}

	if err := o.validatePeers(plan); err != nil {
		return err
	}

	peers := make([]tunnel.PeerConfig, 0, len(plan.Peers))
	for _, peer := range plan.Peers {
		endpoint := netip.AddrPort{}
		if peer.PublicKey == o.relay.String() {
			endpoint = config.BridgeEndpoint
		}

		peers = append(peers, tunnel.PeerConfig{
			PublicKey:           peer.PublicKey,
			Endpoint:            endpoint,
			AllowedPrefixes:     peer.AllowedPrefixes,
			PersistentKeepalive: time.Duration(peer.KeepaliveSecs) * time.Second,
		})
	}

	desired, err := tunnel.BuildWireGuardConfigWithListenPort(
		config.PrivateKey,
		config.ListenPort,
		peers,
	)
	if err != nil {
		return err
	}

	for index, peer := range plan.Peers {
		if peer.PublicKey != o.relay.String() {
			desired.Peers[index].Endpoint = nil
		}
	}

	if err := validateNativeExecutable(
		o.settings.wgPath,
		o.settings.binaryRoot,
		o.settings.ownerUID,
	); err != nil {
		return err
	}

	return o.driver.Configure(ctx, name, desired)
}

func (o *nativeOperations) validatePeers(plan networkplan.Plan) error {
	if plan.Revoked || !o.overlayAddress(plan.OverlayAddress) ||
		len(plan.Peers) == 0 || len(plan.Peers) > 64 {
		return errors.New("native plan requires a bounded signed gateway peer set")
	}

	seen := make(map[wgtypes.Key]bool, len(plan.Peers))
	selected := false
	var previous []netip.Prefix
	for _, peer := range plan.Peers {
		key, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil || key == (wgtypes.Key{}) || key == o.pinned || seen[key] ||
			key.String() != peer.PublicKey || len(peer.AllowedPrefixes) == 0 ||
			peer.KeepaliveSecs < 0 || peer.KeepaliveSecs > 65535 {
			return errors.New("native plan has invalid or duplicate gateway identities")
		}

		seen[key] = true
		selected = selected || key == o.relay
		for _, prefix := range peer.AllowedPrefixes {
			if prefix.Contains(plan.OverlayAddress.Addr()) ||
				!o.overlayAddress(prefix) && !o.privateRoute(prefix) {
				return errors.New("native peer prefix is outside provisioned scope")
			}

			for _, other := range previous {
				if prefix.Overlaps(other) {
					return errors.New("native gateway prefixes have conflicting owners")
				}
			}
		}

		previous = append(previous, peer.AllowedPrefixes...)
	}

	if !selected {
		return errors.New("native plan omits the provisioned relay gateway")
	}

	return nil
}

func (o *nativeOperations) Address(ctx context.Context, name string, address netip.Prefix) error {
	if _, err := o.ownedTunnel(ctx, name, true); err != nil {
		return err
	}

	return o.darwinEffects.Address(ctx, name, address)
}

func (o *nativeOperations) AddRoute(ctx context.Context, name string, route netip.Prefix) error {
	if _, err := o.ownedTunnel(ctx, name, true); err != nil {
		return err
	}

	return o.darwinEffects.AddRoute(ctx, name, route)
}

func (o *nativeOperations) SetDNS(ctx context.Context, resolver networkplan.Resolver) error {
	marker, err := o.readMarker()
	if err != nil {
		return err
	}

	if _, err := o.ownedTunnel(ctx, marker.Name, true); err != nil {
		return err
	}

	return o.darwinEffects.SetDNS(ctx, resolver)
}

func (o *nativeOperations) RemoveRoute(ctx context.Context, name string, route netip.Prefix) error {
	if _, err := o.ownedTunnel(ctx, name, true); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// A disappeared daemon may release utun for another VPN. Only forget
		// a route proven absent; never delete a route through a reused name.
		if !o.privateRoute(route) {
			return ErrOwnershipConflict
		}

		output, inspectErr := o.runner.Run(ctx, darwinRoute, "-n", "get", "-inet", route.String())
		if inspectErr != nil {
			return inspectErr
		}

		actual, _, parseErr := parseDarwinRoute(output)
		if parseErr != nil {
			return parseErr
		}
		if actual == route {
			return ErrOwnershipConflict
		}

		return nil
	}

	return o.darwinEffects.RemoveRoute(ctx, name, route)
}

func (o *nativeOperations) CloseTunnel(ctx context.Context, name string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !utunName.MatchString(name) {
		return ErrOwnershipConflict
	}

	marker, markerErr := o.readMarker()

	actual, nameErr := o.readName()
	if errors.Is(markerErr, os.ErrNotExist) && errors.Is(nameErr, os.ErrNotExist) {
		if _, err := os.Lstat(o.socketPath(name)); errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return ErrOwnershipConflict
	}
	if markerErr != nil || marker.Name != name ||
		nameErr != nil && !errors.Is(nameErr, os.ErrNotExist) ||
		nameErr == nil && actual != name {
		return errors.Join(ErrOwnershipConflict, markerErr, nameErr)
	}

	_, socketErr := o.verifySocket(marker)
	if socketErr != nil && !errors.Is(socketErr, os.ErrNotExist) {
		return socketErr
	}

	if socketErr == nil {
		if nameErr != nil {
			return ErrOwnershipConflict
		}

		device, err := o.driver.Device(ctx, name)
		if err != nil {
			return err
		}
		if device == nil || device.PublicKey != o.pinned && device.PublicKey != (wgtypes.Key{}) {
			return ErrOwnershipConflict
		}

		if _, err := o.verifySocket(marker); err != nil {
			return err
		}

		if err := os.Remove(o.socketPath(name)); err != nil {
			return err
		}
	}

	if err := os.Remove(o.namePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.Remove(o.markerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return syncDirectory(filepath.Dir(o.policy.JournalPath))
}

func (o *nativeOperations) ownedTunnel(
	ctx context.Context,
	name string,
	requireConfigured bool,
) (tunnelOwnership, error) {
	if !utunName.MatchString(name) {
		return tunnelOwnership{}, ErrOwnershipConflict
	}

	actual, err := o.readName()
	if err != nil || actual != name {
		return tunnelOwnership{}, errors.Join(ErrOwnershipConflict, err)
	}

	marker, err := o.readMarker()
	if err != nil || marker.Name != name {
		return tunnelOwnership{}, errors.Join(ErrOwnershipConflict, err)
	}

	if _, err := o.verifySocket(marker); err != nil {
		return marker, err
	}

	device, err := o.driver.Device(ctx, name)
	if err != nil {
		return marker, err
	}
	if device == nil || device.PublicKey != o.pinned &&
		(requireConfigured || device.PublicKey != (wgtypes.Key{})) {
		return marker, ErrOwnershipConflict
	}

	_, err = o.verifySocket(marker)

	return marker, err
}

func (o *nativeOperations) captureOwnership(
	ctx context.Context,
	name string,
) (tunnelOwnership, error) {
	stat, err := o.socketStat(name)
	if err != nil {
		return tunnelOwnership{}, err
	}

	device, err := o.driver.Device(ctx, name)
	if err != nil {
		return tunnelOwnership{}, err
	}
	if device == nil || device.PublicKey != o.pinned && device.PublicKey != (wgtypes.Key{}) {
		return tunnelOwnership{}, ErrOwnershipConflict
	}

	return tunnelOwnership{
		Version:   1,
		Name:      name,
		PublicKey: o.pinned.String(),
		Device:    uint64(stat.Dev),
		Inode:     stat.Ino,
	}, nil
}

func (o *nativeOperations) socketStat(name string) (*syscall.Stat_t, error) {
	parent, err := os.Lstat(o.settings.socketDir)
	if err != nil {
		return nil, err
	}

	owner, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 ||
		owner.Uid != uint32(o.settings.ownerUID) {
		return nil, ErrOwnershipConflict
	}

	info, err := os.Lstat(o.socketPath(name))
	if err != nil {
		return nil, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(o.settings.ownerUID) {
		return nil, ErrOwnershipConflict
	}

	return stat, nil
}

func (o *nativeOperations) verifySocket(marker tunnelOwnership) (*syscall.Stat_t, error) {
	stat, err := o.socketStat(marker.Name)
	if err != nil {
		return nil, err
	}
	if uint64(stat.Dev) != marker.Device || stat.Ino != marker.Inode {
		return nil, ErrOwnershipConflict
	}

	return stat, nil
}

func (o *nativeOperations) readName() (string, error) {
	info, err := os.Lstat(o.namePath())
	if err != nil {
		return "", err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
		stat.Uid != uint32(o.settings.ownerUID) || stat.Nlink != 1 || info.Size() > 32 {
		return "", ErrOwnershipConflict
	}

	data, err := os.ReadFile(o.namePath())
	name := strings.TrimSpace(string(data))
	if err != nil || !utunName.MatchString(name) {
		return "", errors.Join(ErrOwnershipConflict, err)
	}

	return name, nil
}

func (o *nativeOperations) readMarker() (marker tunnelOwnership, result error) {
	store, err := localstate.Open(o.markerPath())
	if err != nil {
		return marker, err
	}
	defer func() { result = errors.Join(result, store.Close()) }()

	data, err := store.Read()
	if err != nil {
		return marker, err
	}
	if len(data) > 1024 || json.Unmarshal(data, &marker) != nil || marker.Version != 1 ||
		!utunName.MatchString(
			marker.Name,
		) || marker.PublicKey != o.pinned.String() || marker.Inode == 0 {
		return marker, ErrOwnershipConflict
	}

	return marker, nil
}

func (o *nativeOperations) saveMarker(marker tunnelOwnership) (result error) {
	store, err := localstate.Open(o.markerPath())
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, store.Close()) }()

	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}

	return store.Replace(data)
}

func (o *nativeOperations) namePath() string   { return o.policy.JournalPath + ".name" }
func (o *nativeOperations) markerPath() string { return o.policy.JournalPath + ".tunnel" }
func (o *nativeOperations) socketPath(name string) string {
	return filepath.Join(o.settings.socketDir, name+".sock")
}

func validateNativeExecutable(path, trustedRoot string, ownerUID int) error {
	if path != filepath.Clean(path) || trustedRoot != filepath.Clean(trustedRoot) ||
		!filepath.IsAbs(path) || !filepath.IsAbs(trustedRoot) {
		return errors.New("native executable path must be fixed and absolute")
	}

	relative, err := filepath.Rel(trustedRoot, path)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ErrOwnershipConflict
	}

	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect installed native executable: %w", err)
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(ownerUID) || info.Mode().Perm()&0o022 != 0 ||
			current == path && (!info.Mode().IsRegular() || info.Mode().Perm()&0o100 == 0) ||
			current != path && !info.IsDir() {
			return ErrOwnershipConflict
		}
		if current == trustedRoot {
			return nil
		}
	}
}
