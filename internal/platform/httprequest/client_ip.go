// Package httprequest contains shared transport observations, never authentication.
package httprequest

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP honors forwarded addresses only behind explicitly trusted proxies.
// Invalid remote addresses have no public IP representation.
func ClientIP(request *http.Request, trusted []netip.Prefix) string {
	remote := request.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}

	remoteAddr, err := netip.ParseAddr(remote)
	if err != nil {
		return ""
	}

	for _, prefix := range trusted {
		if !prefix.Contains(remoteAddr) {
			continue
		}

		// Walk from the nearest proxy toward the original client. Trusted
		// entries are skipped, and the first untrusted address becomes the
		// limiter key; prepended spoofed values cannot displace a trusted chain.
		forwarded := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
		for index := len(forwarded) - 1; index >= 0; index-- {
			candidate, parseErr := netip.ParseAddr(strings.TrimSpace(forwarded[index]))
			if parseErr != nil {
				continue
			}

			isTrusted := false
			for _, trustedPrefix := range trusted {
				if trustedPrefix.Contains(candidate) {
					isTrusted = true
					break
				}
			}

			if !isTrusted {
				return candidate.String()
			}
		}

		return remoteAddr.String()
	}

	return remoteAddr.String()
}
