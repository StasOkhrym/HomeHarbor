package protocol

import "testing"

func TestNegotiateSelectsCurrentVersion(t *testing.T) {
	result, err := Negotiate(Hello{Versions: []uint16{1}, Capabilities: []string{CapabilityRelay, CapabilityDirectUDP}})
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
