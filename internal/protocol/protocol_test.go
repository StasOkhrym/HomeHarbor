package protocol

import (
	"net/netip"
	"testing"
)

func TestNegotiateSelectsCurrentVersion(t *testing.T) {
	result, err := Negotiate(
		Hello{
			Versions:     []uint16{1},
			Capabilities: []string{CapabilityUDPPair, CapabilityDirectUDP},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if result.Version != 1 || !result.Has(CapabilityUDPPair) {
		t.Fatalf("result = %#v", result)
	}
}

func TestNegotiateRequiresRelayCapability(t *testing.T) {
	_, err := Negotiate(Hello{Versions: []uint16{1}, Capabilities: []string{CapabilityDirectUDP}})

	if err == nil || err.Code != ErrorUpgradeRequired {
		t.Fatalf("error = %#v", err)
	}
}

func TestCandidateUpdateValidateAcceptsBoundedEndpoints(t *testing.T) {
	update := CandidateUpdate{
		DestinationDeviceID: "gateway",
		Candidates: []Candidate{
			{Type: CandidateHost, Address: "192.168.1.10:51820", Priority: 200},
			{Type: CandidateServerReflexive, Address: "203.0.113.10:51820", Priority: 100},
		},
	}

	if err := update.Validate(); err != nil {
		t.Fatal(err)
	}

	if got := netip.MustParseAddrPort(update.Candidates[0].Address).Port(); got != 51820 {
		t.Fatalf("candidate port = %d", got)
	}
}

func TestCandidateUpdateValidateRejectsUnsafeCandidates(t *testing.T) {
	cases := []CandidateUpdate{
		{
			Candidates: []Candidate{
				{Type: CandidateHost, Address: "192.168.1.10:51820", Priority: 1},
			},
		},
		{
			DestinationDeviceID: "gateway",
			Candidates: []Candidate{
				{Type: "unknown", Address: "192.168.1.10:51820", Priority: 1},
			},
		},
		{
			DestinationDeviceID: "gateway",
			Candidates: []Candidate{
				{Type: CandidateHost, Address: "0.0.0.0:51820", Priority: 1},
			},
		},
		{
			DestinationDeviceID: "gateway",
			Candidates: []Candidate{
				{Type: CandidateHost, Address: "192.168.1.10:0", Priority: 1},
			},
		},
		{
			DestinationDeviceID: "gateway",
			Candidates: []Candidate{
				{Type: CandidateHost, Address: "192.168.1.10:51820", Priority: 0},
			},
		},
		{
			DestinationDeviceID: "gateway",
			Candidates: []Candidate{
				{Type: CandidateHost, Address: "192.168.1.10:51820", Priority: 1},
				{Type: CandidateHost, Address: "192.168.1.10:51820", Priority: 2},
			},
		},
	}
	for index, update := range cases {
		if err := update.Validate(); err == nil {
			t.Errorf("case %d: Validate() error=nil", index)
		}
	}
}

func TestCandidateUpdateValidateRejectsOversizedList(t *testing.T) {
	update := CandidateUpdate{
		DestinationDeviceID: "gateway",
		Candidates:          make([]Candidate, maxCandidates+1),
	}
	for index := range update.Candidates {
		update.Candidates[index] = Candidate{
			Type: CandidateHost,
			Address: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.10"), uint16(51820+index)).
				String(),
			Priority: uint32(index + 1),
		}
	}

	if err := update.Validate(); err == nil {
		t.Fatal("Validate() error=nil")
	}
}
