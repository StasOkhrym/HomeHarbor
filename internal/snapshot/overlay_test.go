package snapshot

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocateOverlayAddressSkipsReservedAndUsedHosts(t *testing.T) {
	pool := netip.MustParsePrefix("10.200.0.0/29")

	address, err := AllocateOverlayAddress(pool, []string{"10.200.0.1/32", "10.200.0.2/32"})
	if err != nil {
		t.Fatal(err)
	}

	if address.String() != "10.200.0.3/32" {
		t.Fatalf("allocated address=%s", address)
	}
}

func TestAllocateOverlayAddressRejectsPublicAndDefaultPools(t *testing.T) {
	for _, pool := range []string{"0.0.0.0/0", "192.0.2.0/24", "203.0.113.0/24"} {
		if _, err := AllocateOverlayAddress(netip.MustParsePrefix(pool), nil); !errors.Is(err, ErrInvalidOverlayPool) {
			t.Fatalf("pool %s error=%v", pool, err)
		}
	}
	if address, err := AllocateOverlayAddress(netip.MustParsePrefix("100.64.0.0/30"), nil); err != nil || address.String() != "100.64.0.1/32" {
		t.Fatalf("CGNAT pool address=%s error=%v", address, err)
	}
}

func TestAllocateOverlayAddressReportsExhaustionAndInvalidUsedState(t *testing.T) {
	pool := netip.MustParsePrefix("10.0.0.0/30")
	if _, err := AllocateOverlayAddress(pool, []string{"10.0.0.1/32", "10.0.0.2/32"}); !errors.Is(err, ErrOverlayPoolExhausted) {
		t.Fatalf("exhaustion error=%v", err)
	}
	if _, err := AllocateOverlayAddress(pool, []string{"not-an-address"}); !errors.Is(err, ErrInvalidOverlayPool) {
		t.Fatalf("invalid used error=%v", err)
	}
}
