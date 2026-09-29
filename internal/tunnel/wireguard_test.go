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
	config, err := BuildWireGuardConfig(local.PrivateKey, []PeerConfig{{PublicKey: remote.PublicKey, Endpoint: netip.MustParseAddrPort("203.0.113.1:51820"), AllowedPrefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, PersistentKeepalive: 25 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	if config.PrivateKey == nil || len(config.Peers) != 1 || config.Peers[0].Endpoint.String() != "203.0.113.1:51820" {
		t.Fatalf("config=%#v", config)
	}
}
