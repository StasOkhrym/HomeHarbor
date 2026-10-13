//go:build darwin || linux

package macos

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeTunnelDriver struct {
	socketDir string
	listener  *net.UnixListener
	path      string
	nameFile  string
	config    wgtypes.Config
	key       wgtypes.Key
	nameOnly  bool
}

func (f *fakeTunnelDriver) Launch(_ context.Context, path, nameFile string) error {
	f.path, f.nameFile = path, nameFile

	if err := os.WriteFile(nameFile, []byte("utun7\n"), 0o400); err != nil {
		return err
	}

	if f.nameOnly {
		return errors.New("injected UAPI startup failure")
	}

	listener, err := net.ListenUnix(
		"unix",
		&net.UnixAddr{Name: filepath.Join(f.socketDir, "utun7.sock"), Net: "unix"},
	)
	if err != nil {
		return err
	}

	listener.SetUnlinkOnClose(false)
	f.listener = listener

	return nil
}

func (f *fakeTunnelDriver) Configure(_ context.Context, _ string, config wgtypes.Config) error {
	f.config = config

	f.key = config.PrivateKey.PublicKey()

	return nil
}

func (f *fakeTunnelDriver) Device(context.Context, string) (*wgtypes.Device, error) {
	return &wgtypes.Device{PublicKey: f.key}, nil
}

func nativeOperationsFixture(
	t *testing.T,
) (*nativeOperations, HelperPolicy, nativeSettings, *fakeTunnelDriver, *fakeEffectRunner, HelperRequest) {
	t.Helper()
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)
	dir := t.TempDir()
	binary := filepath.Join(dir, "wireguard-go")

	if err := os.WriteFile(binary, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}

	socketDir, err := os.MkdirTemp("/tmp", "hh-sock-")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	resolverDir := t.TempDir()
	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(dir, "journal.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		RelayPeerPublicKey:      plan.Peers[0].PublicKey,
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	settings := nativeSettings{
		binaryPath: binary, wgPath: binary, binaryRoot: dir, socketDir: socketDir,
		resolverDir: resolverDir, ownerUID: os.Geteuid(),
	}
	driver := &fakeTunnelDriver{socketDir: socketDir}
	t.Cleanup(func() {
		if driver.listener != nil {
			_ = driver.listener.Close()
		}
	})
	runner := &fakeEffectRunner{
		output: "destination: 172.29.50.0\nmask: 255.255.255.0\ninterface: utun7\n",
	}

	ops, err := newNativeOperations(policy, settings, driver, runner)
	if err != nil {
		t.Fatal(err)
	}

	request := HelperRequest{
		Version:    1,
		Action:     "apply",
		Envelope:   envelope,
		Plan:       plan,
		PrivateKey: privateKey,
	}

	return ops, policy, settings, driver, runner, request
}

func TestNativeOperationsApplyAndRecoverOnlyOwnedTunnel(t *testing.T) {
	ops, policy, settings, driver, runner, request := nativeOperationsFixture(t)

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	if driver.path != settings.binaryPath || driver.nameFile != policy.JournalPath+".name" {
		t.Fatalf("unexpected native process inputs: %q %q", driver.path, driver.nameFile)
	}

	config := driver.config

	if config.PrivateKey == nil || config.PrivateKey.String() != request.PrivateKey ||
		config.ListenPort == nil ||
		*config.ListenPort != 51820 ||
		!config.ReplacePeers ||
		len(config.Peers) != 1 {
		t.Fatal("native WireGuard config lost pinned identity or peer replacement")
	}

	peer := config.Peers[0]

	if peer.Endpoint == nil || peer.Endpoint.String() != "127.0.0.1:51822" ||
		len(peer.AllowedIPs) != 2 ||
		peer.AllowedIPs[0].String() != "10.200.0.2/32" ||
		peer.AllowedIPs[1].String() != "172.29.50.0/24" {
		t.Fatalf("native peer widened or lost signed routes: %+v", peer)
	}

	if _, err := os.Stat(filepath.Join(settings.resolverDir, "sandbox.home.arpa")); err != nil {
		t.Fatal(err)
	}

	// A new helper invocation must recover the same ownership from disk.
	recovered, err := newNativeOperations(policy, settings, driver, runner)
	if err != nil {
		t.Fatal(err)
	}

	closeRequest := HelperRequest{Version: 1, Action: "close", Owner: helperOwner(policy.Authority)}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, closeRequest)),
		policy,
		501,
		recovered,
	); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		filepath.Join(settings.resolverDir, "sandbox.home.arpa"),
		filepath.Join(settings.socketDir, "utun7.sock"),
		policy.JournalPath + ".name", policy.JournalPath + ".tunnel",
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("owned resource remains after recovered close: %s: %v", path, err)
		}
	}
}

func TestNativeTunnelCleanupRecoversPartiallyRemovedFiles(t *testing.T) {
	ops, policy, settings, _, _, request := nativeOperationsFixture(t)
	ctx := context.Background()

	if err := ExecuteHelper(
		ctx,
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{filepath.Join(settings.socketDir, "utun7.sock"), policy.JournalPath + ".name"} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}

	if err := ops.CloseTunnel(ctx, "utun7"); err != nil {
		t.Fatalf("interrupted tunnel cleanup cannot finish: %v", err)
	}

	if _, err := os.Lstat(policy.JournalPath + ".tunnel"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ownership marker survived completed cleanup: %v", err)
	}
}

func TestNativeOperationsPreserveReplacedSocketAndRoutes(t *testing.T) {
	ops, policy, settings, _, runner, request := nativeOperationsFixture(t)
	ctx := context.Background()

	if err := ExecuteHelper(
		ctx,
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(settings.socketDir, "utun7.sock")

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = foreign.Close() }()

	before := len(runner.calls)

	if err := ops.RemoveRoute(
		ctx,
		"utun7",
		netip.MustParsePrefix("172.29.50.0/24"),
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("route through replaced tunnel accepted: %v", err)
	}

	if len(runner.calls) != before {
		t.Fatal("route cleanup reached host after tunnel replacement")
	}

	if err := ops.CloseTunnel(ctx, "utun7"); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("replaced socket deleted: %v", err)
	}

	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("foreign socket lost: %v", err)
	}
}

func TestNativeOperationsPreserveRouteAfterDaemonDisappears(t *testing.T) {
	ops, policy, settings, _, runner, request := nativeOperationsFixture(t)
	ctx := context.Background()

	if err := ExecuteHelper(
		ctx,
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(filepath.Join(settings.socketDir, "utun7.sock")); err != nil {
		t.Fatal(err)
	}

	before := len(runner.calls)

	if err := ops.RemoveRoute(
		ctx,
		"utun7",
		netip.MustParsePrefix("172.29.50.0/24"),
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("route through reused utun name deleted: %v", err)
	}

	if len(runner.calls) != before+1 || runner.calls[before].args[1] != "get" {
		t.Fatalf("vanished daemon cleanup mutated route: %+v", runner.calls[before:])
	}
}

func TestNativePreflightRejectsWritableBinaryAndAmbiguousGateway(t *testing.T) {
	ops, _, settings, driver, _, request := nativeOperationsFixture(t)

	if err := os.Chmod(settings.binaryPath, 0o720); err != nil {
		t.Fatal(err)
	}

	if err := ops.Prepare(
		context.Background(),
		request.Plan,
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("writable native binary accepted: %v", err)
	}

	if err := os.Chmod(settings.binaryPath, 0o700); err != nil {
		t.Fatal(err)
	}

	request.Plan.Peers = append(request.Plan.Peers, request.Plan.Peers[0])

	if err := ops.Prepare(context.Background(), request.Plan); err == nil {
		t.Fatal("native plan accepted duplicate gateway identities")
	}

	if driver.path != "" {
		t.Fatal("invalid preflight started native process")
	}
}

func TestNativeDriverLaunchUsesPrivateNameAndCleanEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wireguard-go")
	script := "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = utun ] || exit 9\n[ -z \"$HOMEHARBOR_INHERITED_TEST\" ] || exit 10\n[ -n \"$WG_TUN_NAME_FILE\" ] || exit 11\nprintf 'utun7\\n' > \"$WG_TUN_NAME_FILE\"\n"

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOMEHARBOR_INHERITED_TEST", "must-not-reach-root-child")
	namePath := filepath.Join(dir, "native.name")

	if err := (systemTunnelDriver{}).Launch(context.Background(), path, namePath); err != nil {
		t.Fatalf("fixed launch protocol failed: %v", err)
	}

	data, err := os.ReadFile(namePath)

	if err != nil || string(data) != "utun7\n" {
		t.Fatalf("name file was not passed privately: %q, %v", data, err)
	}
}

func TestNativeDriverConfiguresWithPrivateStdinAndReadsOnlyPublicKey(t *testing.T) {
	_, _, plan, _, privateText := nativeFixtureWithKey(t)

	private, err := wgtypes.ParseKey(privateText)
	if err != nil {
		t.Fatal(err)
	}

	public, err := wgtypes.ParseKey(plan.Peers[0].PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	port, keepalive := 51820, 25*time.Second

	_, allowed, err := net.ParseCIDR("172.29.50.0/24")
	if err != nil {
		t.Fatal(err)
	}

	config := wgtypes.Config{
		PrivateKey:   &private,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: public,
				Endpoint:  net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:51822")),
				AllowedIPs: []net.IPNet{
					*allowed,
				},
				ReplaceAllowedIPs:           true,
				PersistentKeepaliveInterval: &keepalive,
			},
		},
	}

	other, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, otherPrefix, err := net.ParseCIDR("10.200.0.4/32")
	if err != nil {
		t.Fatal(err)
	}

	config.Peers = append(config.Peers, wgtypes.PeerConfig{
		PublicKey: other.PublicKey(), AllowedIPs: []net.IPNet{*otherPrefix},
		ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive,
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "wg")
	script := "#!/bin/sh\n[ \"$#\" -eq 3 ] || exit 9\ncase \"$1:$2:$3\" in\nsetconf:utun7:/dev/stdin) cat > \"$0.capture\" ;;\nshow:utun7:public-key) printf '%s\\n' '" + private.PublicKey().
		String() +
		"' ;;\n*) exit 10 ;;\nesac\n"

	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	driver := systemTunnelDriver{wgPath: path}

	if err := driver.Configure(context.Background(), "utun7", config); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path + ".capture")
	if err != nil {
		t.Fatal(err)
	}

	want := "[Interface]\nPrivateKey = " + privateText + "\nListenPort = 51820\n\n[Peer]\nPublicKey = " + public.String() + "\nEndpoint = 127.0.0.1:51822\nAllowedIPs = 172.29.50.0/24\nPersistentKeepalive = 25\n"
	want += "\n[Peer]\nPublicKey = " + other.PublicKey().
		String() +
		"\nAllowedIPs = 10.200.0.4/32\nPersistentKeepalive = 25\n"

	if string(data) != want {
		t.Fatal("private stdin WireGuard configuration differs from pinned inputs")
	}

	device, err := driver.Device(context.Background(), "utun7")

	if err != nil || device.PublicKey != private.PublicKey() {
		t.Fatalf("public identity inspection failed: %v", err)
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat >&2\nexit 17\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := driver.Configure(
		context.Background(),
		"utun7",
		config,
	); err == nil ||
		strings.Contains(err.Error(), privateText) {
		t.Fatal("failed native configuration lost its error or exposed private stdin")
	}
}

type forbiddenHelperInput struct{ read bool }

func (r *forbiddenHelperInput) Read([]byte) (int, error) {
	r.read = true
	return 0, errors.New("private input must not be read")
}

func TestSystemHelperRequiresRootMacOSBeforeReadingInput(t *testing.T) {
	if runtime.GOOS == "darwin" && os.Geteuid() == 0 {
		t.Skip("requires an unprivileged process or a non-macOS host")
	}

	input := &forbiddenHelperInput{}

	if err := RunSystemHelper(context.Background(), input); err == nil || input.read {
		t.Fatalf("unauthorized system helper consumed input: read=%v err=%v", input.read, err)
	}
}

func TestNativeStartupFailureRemovesOnlyStaleName(t *testing.T) {
	ops, policy, _, driver, _, request := nativeOperationsFixture(t)
	driver.nameOnly = true

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err == nil {
		t.Fatal("failed UAPI startup reported success")
	}

	if _, err := os.Lstat(policy.JournalPath + ".name"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed startup left unrecoverable name file: %v", err)
	}

	state, err := readJournal(policy.JournalPath)

	if err != nil || state.Phase != "" || state.AppliedRevision != 0 {
		t.Fatalf("failed startup lost clean recovery state: %+v, %v", state, err)
	}
}

func TestNativeRecoveryRejectsUnsafeToolsBeforeAnyDriverCall(t *testing.T) {
	_, policy, settings, driver, runner, _ := nativeOperationsFixture(t)

	if err := os.Chmod(settings.wgPath, 0o720); err != nil {
		t.Fatal(err)
	}

	if _, err := newNativeOperations(
		policy,
		settings,
		driver,
		runner,
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("recovery accepted a writable executable: %v", err)
	}
}

func TestNativeConfigurationKeepsAllSignedPeersAndScopesRelayEndpoint(t *testing.T) {
	ops, policy, _, driver, _, request := nativeOperationsFixture(t)
	ctx := context.Background()

	if err := ExecuteHelper(
		ctx,
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	other, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	peer := request.Plan.Peers[0]

	peer.PublicKey = other.PublicKey().String()
	peer.AllowedPrefixes = []netip.Prefix{netip.MustParsePrefix("10.200.0.4/32")}
	request.Plan.Peers = append(request.Plan.Peers, peer)

	if err := ops.Prepare(ctx, request.Plan); err != nil {
		t.Fatalf("valid additional gateway peer rejected: %v", err)
	}

	config := policy.Tunnel
	config.PrivateKey = request.PrivateKey

	if err := ops.Configure(ctx, "utun7", request.Plan, config); err != nil {
		t.Fatal(err)
	}

	if len(driver.config.Peers) != 2 || driver.config.Peers[0].Endpoint == nil ||
		driver.config.Peers[1].Endpoint != nil {
		t.Fatal(
			"native configuration dropped topology or reused a relay endpoint for another gateway",
		)
	}
}

func TestSystemHelperRequiresCanonicalSudoOwner(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "+501", "0501", "invalid", "2147483648"} {
		if _, err := systemHelperCaller(0, value); err == nil {
			t.Fatalf("invalid sudo owner accepted: %q", value)
		}
	}

	if uid, err := systemHelperCaller(0, "501"); err != nil || uid != 501 {
		t.Fatalf("canonical sudo owner rejected: %d %v", uid, err)
	}

	if _, err := systemHelperCaller(501, "501"); err == nil {
		t.Fatal("unprivileged process trusted a forged sudo environment")
	}
}

func TestNativeDriverHonorsOperationDeadline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wireguard-go")

	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	if err := (systemTunnelDriver{}).Launch(
		ctx,
		path,
		filepath.Join(dir, "name"),
	); !errors.Is(
		err,
		context.DeadlineExceeded,
	) {
		t.Fatalf("native process ignored operation deadline: %v", err)
	}
}

func TestNativePreflightRejectsPeerClaimingLocalOverlay(t *testing.T) {
	ops, _, _, _, _, request := nativeOperationsFixture(t)
	request.Plan.Peers[0].AllowedPrefixes[0] = request.Plan.OverlayAddress

	if err := ops.Prepare(context.Background(), request.Plan); err == nil {
		t.Fatal("gateway peer claimed the local client's overlay identity")
	}
}

func TestNativeCleanupPreservesChangedTunnelPublicKey(t *testing.T) {
	ops, policy, settings, driver, runner, request := nativeOperationsFixture(t)
	ctx := context.Background()

	if err := ExecuteHelper(
		ctx,
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		ops,
	); err != nil {
		t.Fatal(err)
	}

	foreign, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	driver.key = foreign.PublicKey()
	before := len(runner.calls)

	if err := ops.RemoveRoute(
		ctx,
		"utun7",
		netip.MustParsePrefix("172.29.50.0/24"),
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("changed tunnel identity lost route ownership protection: %v", err)
	}

	if len(runner.calls) != before {
		t.Fatal("changed tunnel identity caused a route mutation")
	}

	if err := ops.CloseTunnel(ctx, "utun7"); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("changed tunnel identity closed: %v", err)
	}

	if _, err := os.Lstat(filepath.Join(settings.socketDir, "utun7.sock")); err != nil {
		t.Fatalf("foreign tunnel socket removed: %v", err)
	}
}
