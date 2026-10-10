package protocol

import "testing"

func TestRelayControlURLMatchesOnlyCanonicalWSSRoute(t *testing.T) {
	for _, tc := range []struct {
		url   string
		valid bool
	}{
		{"wss://relay.example/relay/udp", true},
		{"wss://relay.example:443/relay/udp", true},
		{"wss://relay.example/relay/udp/v2", false},
		{"wss://relay.example/relay/v1", false},
		{"wss://relay.example/relay/udp/", false},
		{"wss://relay.example/relay/%75dp", false},
		{"wss://relay.example/relay/udp?ticket=secret", false},
		{"wss://relay.example/relay/udp#", false},
		{"wss://relay.example:0/relay/udp", false},
		{"ws://relay.example/relay/udp", false},
		{"wss://user:password@relay.example/relay/udp", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			err := ValidateRelayControlURL(tc.url)

			if (err == nil) != tc.valid {
				t.Fatalf("ValidateRelayControlURL(%q) error=%v, valid=%v", tc.url, err, tc.valid)
			}
		})
	}
}
