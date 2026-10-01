package protocol

import (
	"net/netip"
	"testing"
	"time"
)

func TestNegotiateSelectsCurrentVersion(t *testing.T) {
	result, err := Negotiate(
		Hello{Versions: []uint16{1}, Capabilities: []string{CapabilityRelay, CapabilityDirectUDP}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Version != 1 || !result.Has(CapabilityRelay) {
		t.Fatalf("result = %#v", result)
	}
}

func TestNegotiateRequiresRelayCapability(t *testing.T) {
	_, err := Negotiate(Hello{Versions: []uint16{1}, Capabilities: []string{CapabilityDirectUDP}})

	if err == nil || err.Code != ErrorUpgradeRequired {
		t.Fatalf("error = %#v", err)
	}
}

func TestPathSelectorFallsBackAndRecovers(t *testing.T) {
	selector := NewPathSelector()
	if got := selector.Current(); got != PathRelay {
		t.Fatalf("initial path = %q", got)
	}
	selector.DirectHandshakeSucceeded()
	if got := selector.Current(); got != PathDirect {
		t.Fatalf("direct path = %q", got)
	}
	selector.DirectFailed()
	if got := selector.Current(); got != PathRelay {
		t.Fatalf("fallback path = %q", got)
	}
}

func TestPathSelectorNotifiesTransportWatchersOnChange(t *testing.T) {
	selector := NewPathSelector()
	changes := selector.Changes()
	selector.DirectHandshakeSucceeded()
	select {
	case <-changes:
	case <-time.After(time.Second):
		t.Fatal("direct path change was not published")
	}
	if got := selector.Current(); got != PathDirect {
		t.Fatalf("path=%q, want direct", got)
	}
	nextChanges := selector.Changes()
	selector.DirectFailed()
	select {
	case <-nextChanges:
	case <-time.After(time.Second):
		t.Fatal("relay fallback change was not published")
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
