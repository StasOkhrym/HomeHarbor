package protocol

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const RelayControlPath = "/relay/udp"

// ValidateRelayControlURL accepts the one externally advertised relay route.
// Exact matching prevents a transport capability from reviving an old route.
func ValidateRelayControlURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "wss" || u.Hostname() == "" ||
		u.EscapedPath() != RelayControlPath || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || u.Opaque != "" {
		return errors.New("relay control URL must be a WSS origin with /relay/udp path")
	}

	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return errors.New("relay control URL must have a valid port")
		}
	}

	return nil
}
