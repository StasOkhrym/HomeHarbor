package policy

import (
	"context"
	"net/netip"
	"testing"
)

func TestServiceCreatesMonotonicSnapshots(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(store, Compiler{})
	first, err := service.Replace(
		context.Background(),
		[]Rule{
			{
				ID:             "ssh",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("10.0.0.10/32"),
				Protocol:       ProtocolTCP,
				PortFrom:       22,
				PortTo:         22,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Replace(
		context.Background(),
		[]Rule{
			{
				ID:             "web",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("10.0.0.20/32"),
				Protocol:       ProtocolTCP,
				PortFrom:       443,
				PortTo:         443,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || second.Revision != 2 || second.DefaultAction != ActionDeny {
		t.Fatalf("snapshots=%#v %#v", first, second)
	}
}
