package node

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/platform/config"
)

func signedGatewayConfig(t *testing.T) config.Node {
	t.Helper()
	cfg, _ := guardedRuntimeFixture(t)
	cfg.Identity.ControlURL = "https://control.example.test"
	cfg.Coordination.URL = "wss://control.example.test/api/v1/coordination"
	cfg.Relay.WebSocketURL = "wss://relay.example.test/relay/udp"
	cfg.Relay.SignedPeers = true

	return cfg
}

func TestSignedRelayRuntimeNeedsNoStaticPeerAndConstructorHasNoEffects(t *testing.T) {
	cfg := signedGatewayConfig(t)
	if _, err := NewRuntime(context.Background(), Gateway, cfg); err != nil {
		t.Fatal("signed peers still require static single-peer settings:", err)
	}

	if _, err := os.Stat(cfg.Identity.StatePath); !os.IsNotExist(err) {
		t.Fatal("constructor created private identity")
	}
}

func TestSignedRelayRuntimeRejectsUnsafeAndMixedModesBeforeIdentityCreation(t *testing.T) {
	for name, mutate := range map[string]func(*config.Node){
		"fixed session":          func(c *config.Node) { c.Relay.SessionID = "legacy" },
		"fixed destination":      func(c *config.Node) { c.Relay.DestinationDevice = "legacy" },
		"fixed ticket":           func(c *config.Node) { c.Relay.Ticket = "SECRET-MUST-NOT-ESCAPE" },
		"direct path":            func(c *config.Node) { c.Direct.Candidates = "127.0.0.1:51820" },
		"no control":             func(c *config.Node) { c.Identity.ControlURL = "" },
		"plaintext control":      func(c *config.Node) { c.Identity.ControlURL = "http://control.example.test" },
		"plaintext coordination": func(c *config.Node) { c.Coordination.URL = "ws://control.example.test/api/v1/coordination" },
		"non-loopback WG":        func(c *config.Node) { c.Relay.WireGuardAddress = "0.0.0.0:51820" },
		"wrong WG port":          func(c *config.Node) { c.Relay.WireGuardAddress = "127.0.0.1:51821" },
		"zero WG port":           func(c *config.Node) { c.WireGuard.ListenPort = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := signedGatewayConfig(t)

			mutate(&cfg)

			_, err := NewRuntime(context.Background(), Gateway, cfg)

			if err == nil {
				t.Fatal("unsafe managed relay config admitted")
			}
			if strings.Contains(err.Error(), "SECRET-MUST-NOT-ESCAPE") {
				t.Fatal("private input leaked in validation error")
			}

			if _, err := os.Stat(cfg.Identity.StatePath); !os.IsNotExist(err) {
				t.Fatal("invalid config wrote identity")
			}
		})
	}

	cfg := signedGatewayConfig(t)
	if _, err := NewRuntime(context.Background(), Client, cfg); err == nil {
		t.Fatal("client runtime admitted gateway managed-peer mode")
	}
}
