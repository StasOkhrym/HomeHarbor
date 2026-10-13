package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func nativeRuntimeFixture(t *testing.T) config.Node {
	t.Helper()

	root, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	peer, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()

	cfg := config.DefaultClient()
	cfg.Identity.StatePath = filepath.Join(dir, "client.json")
	cfg.Identity.ControlURL = "https://localhost:8443"
	cfg.Identity.CAFile = filepath.Join(dir, "ca.pem")
	cfg.Coordination.URL = "wss://localhost:8443/coordination"
	cfg.Coordination.RootPublicKeyFile = filepath.Join(dir, "root.pub")
	cfg.Coordination.NetworkID = "sandbox-network"
	cfg.Relay.WebSocketURL = "wss://localhost:8444/relay/udp"
	cfg.Relay.SessionID = "sandbox-session"
	cfg.Relay.DestinationDevice = "gateway-1"

	cfg.WireGuard.PeerPublicKey = peer.PublicKey().String()
	cfg.Native = config.NodeNative{
		Enabled: true,
		Overlay: "10.243.0.0/24",
		Private: "10.241.50.0/24",
		Suffix:  "sandbox.home.arpa",
	}

	if err := os.WriteFile(
		cfg.Coordination.RootPublicKeyFile,
		[]byte(base64.RawURLEncoding.EncodeToString(root)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	return cfg
}

func TestNativeRuntimeConstructionUsesSignedAddressesAndHasNoEffects(t *testing.T) {
	cfg := nativeRuntimeFixture(t)
	app, err := NewRuntime(context.Background(), Client, cfg)
	if runtime.GOOS == "darwin" {
		if err != nil || app == nil {
			t.Fatalf("native runtime demanded Linux interface or static policy: %v", err)
		}
	} else if err == nil {
		t.Fatal("native macOS runtime enabled on unsupported platform")
	}

	if _, err := os.Lstat(cfg.Identity.StatePath); !os.IsNotExist(err) {
		t.Fatalf("native constructor wrote identity state: %v", err)
	}
}

func TestNativeValidationRejectsUnboundedOrConflictingStartupOptions(t *testing.T) {
	cfg := nativeRuntimeFixture(t)

	if err := validateNativeRuntime(Client, cfg, "darwin"); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(*config.Node){
		"default overlay":        func(c *config.Node) { c.Native.Overlay = "0.0.0.0/0" },
		"unmasked subnet":        func(c *config.Node) { c.Native.Private = "10.241.50.1/24" },
		"overlapping subnet":     func(c *config.Node) { c.Native.Private = c.Native.Overlay },
		"foreign public subnet":  func(c *config.Node) { c.Native.Private = "203.0.113.0/24" },
		"unsafe suffix":          func(c *config.Node) { c.Native.Suffix = "../../etc" },
		"external bridge":        func(c *config.Node) { c.Relay.ListenAddress = "192.0.2.1:51822" },
		"privileged bridge":      func(c *config.Node) { c.Relay.ListenAddress = "127.0.0.1:80" },
		"same socket":            func(c *config.Node) { c.Relay.ListenAddress = c.Relay.WireGuardAddress },
		"wrong WireGuard socket": func(c *config.Node) { c.Relay.WireGuardAddress = "127.0.0.1:51819" },
		"caller interface":       func(c *config.Node) { c.WireGuard.InterfaceName = "utun7" },
		"caller overlay":         func(c *config.Node) { c.WireGuard.OverlayAddress = "10.243.0.3/32" },
		"caller routes":          func(c *config.Node) { c.WireGuard.Routes = "10.241.50.0/24" },
		"caller prefixes":        func(c *config.Node) { c.WireGuard.AllowedPrefixes = "10.241.50.0/24" },
		"global forwarding":      func(c *config.Node) { c.DNS.EnableForwarding = true },
		"Linux resolver":         func(c *config.Node) { c.DNS.Link = "wg0" },
		"direct mode":            func(c *config.Node) { c.Direct.Candidates = "127.0.0.1:51820" },
		"raw enrollment":         func(c *config.Node) { c.Identity.Token = "legacy-token" },
		"missing TLS trust":      func(c *config.Node) { c.Identity.CAFile = "" },
		"missing coordination":   func(c *config.Node) { c.Coordination.URL = "" },
		"missing control":        func(c *config.Node) { c.Identity.ControlURL = "" },
		"missing relay":          func(c *config.Node) { c.Relay.WebSocketURL = "" },
		"missing peer identity":  func(c *config.Node) { c.WireGuard.PeerPublicKey = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cfg

			mutate(&candidate)

			if err := validateNativeRuntime(Client, candidate, "darwin"); err == nil {
				t.Fatal("unsafe native options accepted")
			}
		})
	}

	for _, platform := range []string{"linux", "windows"} {
		if err := validateNativeRuntime(Client, cfg, platform); err == nil {
			t.Fatalf("native networking enabled on %s", platform)
		}
	}

	if err := validateNativeRuntime(Gateway, cfg, "darwin"); err == nil {
		t.Fatal("gateway enabled native client networking")
	}
}
