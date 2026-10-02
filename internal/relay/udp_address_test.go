package relay

import (
	"net"
	"testing"
)

func TestCloneUDPAddrOwnsIPBytes(t *testing.T) {
	if cloneUDPAddr(nil) != nil {
		t.Fatal("nil address acquired an endpoint")
	}

	original := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 51820, Zone: "eth0"}

	clone := cloneUDPAddr(original)

	if !sameUDPAddr(original, clone) {
		t.Fatal("clone changed endpoint")
	}

	clone.IP[0] ^= 1
	clone.Port++
	clone.Zone = "eth1"

	if !original.IP.Equal(net.ParseIP("fe80::1")) || original.Port != 51820 ||
		original.Zone != "eth0" {
		t.Fatal("mutating the copy changed the owner's endpoint")
	}
}

func TestSameUDPAddrPreservesPortZoneAndIPv6Semantics(t *testing.T) {
	original := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 51820, Zone: "eth0"}
	for _, test := range []struct {
		name  string
		right *net.UDPAddr
		want  bool
	}{
		{"nil", nil, false},
		{"equal IPv6", cloneUDPAddr(original), true},
		{"different port", &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 51821, Zone: "eth0"}, false},
		{"different zone", &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 51820, Zone: "eth1"}, false},
		{"different IP", &net.UDPAddr{IP: net.ParseIP("fe80::2"), Port: 51820, Zone: "eth0"}, false},
		{"IPv4 mapped", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sameUDPAddr(original, test.right); got != test.want {
				t.Fatalf("endpoint match=%v want=%v", got, test.want)
			}
		})
	}

	if sameUDPAddr(nil, original) {
		t.Fatal("nil source matched")
	}
	// net.IP.Equal intentionally handles the 4-byte and IPv4-mapped forms.
	if !sameUDPAddr(
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 1},
		&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1},
	) {
		t.Fatal("equivalent IPv4 encodings did not match")
	}
}
