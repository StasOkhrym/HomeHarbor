package relay

import "net"

// cloneUDPAddr transfers endpoint metadata without sharing mutable IP bytes
// between the UDP reader and a binding owner protected by a different lock.
func cloneUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}

	clone := *address
	clone.IP = append(net.IP(nil), address.IP...)

	return &clone
}

func sameUDPAddr(left, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return false
	}

	// A link-local IPv6 address identifies an endpoint only within its zone.
	return left.Port == right.Port && left.Zone == right.Zone &&
		(right.IP.IsUnspecified() || left.IP.Equal(right.IP))
}
