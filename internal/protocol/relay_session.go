package protocol

// RelaySession is the control API's short-lived relay ticket projection.
type RelaySession struct {
	SessionID           string `json:"session_id"`
	DeviceID            string `json:"device_id"`
	DestinationDeviceID string `json:"destination_device_id"`
	RelayURL            string `json:"relay_url"`
	RelayTransport      string `json:"relay_transport"`
	RelayUDPAddress     string `json:"relay_udp_address,omitempty"`
	Ticket              string `json:"ticket"`
	ExpiresInSeconds    int64  `json:"expires_in_seconds"`
}

type RelaySessionRequest struct {
	SessionID           string   `json:"session_id"`
	DestinationDeviceID string   `json:"destination_device_id"`
	Capabilities        []string `json:"capabilities"`
}
