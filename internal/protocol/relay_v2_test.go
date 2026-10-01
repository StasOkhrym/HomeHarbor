package protocol

import "testing"

func TestUDPV2NegotiatesWithoutLegacyRelayCapability(t *testing.T) {
	negotiated, err := Negotiate(
		Hello{
			Versions:     []uint16{CurrentVersion},
			Capabilities: []string{CapabilityUDPPairV2, CapabilitySplitDNS},
		},
	)
	if err != nil || !negotiated.Has(CapabilityUDPPairV2) || negotiated.Has(CapabilityRelay) {
		t.Fatalf("negotiated=%#v error=%v", negotiated, err)
	}
}
