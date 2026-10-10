package protocol

import "testing"

func TestCanonicalRelayCapabilityOnly(t *testing.T) {
	current, err := Negotiate(
		Hello{Versions: []uint16{CurrentVersion}, Capabilities: []string{"udp_pair"}},
	)

	if err != nil || !current.Has("udp_pair") {
		t.Fatalf("canonical capability rejected: %#v, %v", current, err)
	}

	for _, old := range []string{"udp_pair_v2", "relay-v1"} {
		if _, err := Negotiate(
			Hello{Versions: []uint16{CurrentVersion}, Capabilities: []string{old}},
		); err == nil {
			t.Errorf("obsolete relay capability %q accepted", old)
		}
	}
}

func TestUDPPairNegotiatesWithoutLegacyRelayCapability(t *testing.T) {
	negotiated, err := Negotiate(
		Hello{
			Versions:     []uint16{CurrentVersion},
			Capabilities: []string{CapabilityUDPPair, CapabilitySplitDNS},
		},
	)

	if err != nil || !negotiated.Has(CapabilityUDPPair) || negotiated.Has("relay-v1") {
		t.Fatalf("negotiated=%#v error=%v", negotiated, err)
	}
}
