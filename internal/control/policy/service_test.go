package policy_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/policy"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
)

func TestServiceCreatesMonotonicSnapshots(t *testing.T) {
	store := memorystore.NewRepository()
	service := domainpkg.NewService(store, acl.Compiler{})

	first, err := service.Replace(
		context.Background(),
		[]acl.Rule{
			{
				ID:             "ssh",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("10.0.0.10/32"),
				Protocol:       acl.ProtocolTCP,
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
		[]acl.Rule{
			{
				ID:             "web",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("10.0.0.20/32"),
				Protocol:       acl.ProtocolTCP,
				PortFrom:       443,
				PortTo:         443,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	if first.Revision != 1 || second.Revision != 2 || second.DefaultAction != acl.ActionDeny {
		t.Fatalf("snapshots=%#v %#v", first, second)
	}
}
