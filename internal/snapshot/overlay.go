package snapshot

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrInvalidOverlayPool   = errors.New("invalid overlay address pool")
	ErrOverlayPoolExhausted = errors.New("overlay address pool exhausted")
)

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// AllocateOverlayAddress returns the first unused host address in pool. The
// allocator is intentionally bounded to IPv4 pools from RFC1918 or the
// carrier-grade NAT range; this prevents an accidental default/public route
// from becoming an overlay identity and makes exhaustion deterministic.
// Network and broadcast addresses are reserved, so a /31 or /32 pool has no
// allocatable hosts.
func AllocateOverlayAddress(pool netip.Prefix, used []string) (netip.Prefix, error) {
	if !pool.IsValid() || pool.Addr().BitLen() != 32 || pool.Bits() < 8 || pool.Bits() > 30 || pool.Bits() == 0 {
		return netip.Prefix{}, ErrInvalidOverlayPool
	}
	pool = pool.Masked()
	if !pool.Addr().IsPrivate() && !carrierGradeNAT.Contains(pool.Addr()) {
		return netip.Prefix{}, ErrInvalidOverlayPool
	}
	usedSet := make(map[netip.Addr]struct{}, len(used))
	for _, raw := range used {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.IsValid() || prefix.Bits() != 32 || prefix.Addr().BitLen() != 32 {
			return netip.Prefix{}, fmt.Errorf("%w: used address %q", ErrInvalidOverlayPool, raw)
		}
		usedSet[prefix.Addr()] = struct{}{}
	}
	base := pool.Addr().As4()
	baseValue := binary.BigEndian.Uint32(base[:])
	hostCount := uint32(1) << uint32(32-pool.Bits())
	for offset := uint32(1); offset < hostCount-1; offset++ {
		var candidateBytes [4]byte
		binary.BigEndian.PutUint32(candidateBytes[:], baseValue+offset)
		candidate := netip.AddrFrom4(candidateBytes)
		if _, exists := usedSet[candidate]; exists {
			continue
		}
		return netip.PrefixFrom(candidate, 32), nil
	}
	return netip.Prefix{}, ErrOverlayPoolExhausted
}
