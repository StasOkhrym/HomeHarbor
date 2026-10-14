package tunnel

import (
	"net/netip"
	"testing"
	"time"
)

func TestBuildWireGuardConfig(t *testing.T) {
	local, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	remote, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	config, err := BuildWireGuardConfigWithListenPort(
		local.PrivateKey,
		0,
		[]PeerConfig{
			{
				PublicKey:           remote.PublicKey,
				Endpoint:            netip.MustParseAddrPort("203.0.113.1:51820"),
				AllowedPrefixes:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
				PersistentKeepalive: 25 * time.Second,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if config.PrivateKey == nil || len(config.Peers) != 1 ||
		config.Peers[0].Endpoint.String() != "203.0.113.1:51820" {
		t.Fatalf("config=%#v", config)
	}
}

func TestBuildWireGuardConfigWithListenPort(t *testing.T) {
	local, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	config, err := BuildWireGuardConfigWithListenPort(local.PrivateKey, 51820, nil)
	if err != nil {
		t.Fatal(err)
	}

	if config.ListenPort == nil || *config.ListenPort != 51820 {
		t.Fatalf("listen port=%v", config.ListenPort)
	}
}

func TestBuildWireGuardConfigRejectsDefaultRoute(t *testing.T) {
	local, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	remote, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BuildWireGuardConfigWithListenPort(
		local.PrivateKey,
		0,
		[]PeerConfig{
			{
				PublicKey:       remote.PublicKey,
				AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
	); err == nil {
		t.Fatal("default route was accepted")
	}
}
