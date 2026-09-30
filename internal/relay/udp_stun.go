package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/pion/stun/v3"
)

const stunProbeTimeout = 5 * time.Second

// DiscoverServerReflexive uses the bridge's already-bound UDP socket for a
// STUN binding request. Reusing the socket matters: a NAT may allocate a
// different public port for a separate discovery socket, making the resulting
// candidate unusable for the WireGuard packets this bridge actually carries.
func (b *UDPPairBridge) DiscoverServerReflexive(ctx context.Context, serverURI string) (netip.AddrPort, error) {
	if b == nil || b.udp == nil {
		return netip.AddrPort{}, errors.New("UDP pair bridge is not initialized")
	}
	if ctx == nil {
		return netip.AddrPort{}, errors.New("STUN context is required")
	}
	uri, err := stun.ParseURI(serverURI)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse UDP STUN server: %w", err)
	}
	if uri.Scheme != stun.SchemeTypeSTUN || uri.Proto == stun.ProtoTypeTCP {
		return netip.AddrPort{}, errors.New("STUN server must use the stun: UDP URI scheme")
	}
	server, err := net.ResolveUDPAddr("udp", net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port)))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve STUN server: %w", err)
	}
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("build STUN request: %w", err)
	}
	if _, err := b.udp.WriteToUDP(request.Raw, server); err != nil {
		return netip.AddrPort{}, fmt.Errorf("send STUN request: %w", err)
	}
	deadline := time.Now().Add(stunProbeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	buffer := make([]byte, 1500)
	for time.Now().Before(deadline) {
		readDeadline := time.Now().Add(250 * time.Millisecond)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		if err := b.udp.SetReadDeadline(readDeadline); err != nil {
			return netip.AddrPort{}, err
		}
		n, source, readErr := b.udp.ReadFromUDP(buffer)
		if readErr != nil {
			if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
				if err := ctx.Err(); err != nil {
					return netip.AddrPort{}, err
				}
				continue
			}
			return netip.AddrPort{}, readErr
		}
		if !sameUDPAddr(source, server) || !stun.IsMessage(buffer[:n]) {
			continue
		}
		response := stun.New()
		if err := response.UnmarshalBinary(buffer[:n]); err != nil || response.TransactionID != request.TransactionID || response.Type != stun.BindingSuccess {
			continue
		}
		var mapped stun.XORMappedAddress
		if err := mapped.GetFrom(response); err != nil {
			continue
		}
		ip, err := netip.ParseAddr(mapped.IP.String())
		if err != nil || !ip.IsValid() || ip.IsUnspecified() || mapped.Port == 0 {
			continue
		}
		_ = b.udp.SetReadDeadline(time.Time{})
		return netip.AddrPortFrom(ip, uint16(mapped.Port)), nil
	}
	if err := ctx.Err(); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPort{}, errors.New("STUN binding timed out")
}
