package nft

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/acl"
)

func TestApplierKeepsLastRevisionWhenNftRejectsUpdate(t *testing.T) {
	applier := NewApplier(
		"gt0",
		map[string]netip.Prefix{"client": netip.MustParsePrefix("100.64.0.2/32")},
	)
	var scripts []string

	applyErr := errors.New("nft syntax error")
	applier.run = func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		if len(scripts) == 2 {
			return applyErr
		}

		return nil
	}
	first := acl.Snapshot{
		Revision:      1,
		DefaultAction: acl.ActionDeny,
		Rules: []acl.Rule{
			{
				ID:             "allow-http",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("192.168.1.0/24"),
				Protocol:       acl.ProtocolTCP,
				PortFrom:       443,
				PortTo:         443,
			},
		},
	}
	second := first
	second.Revision = 2

	if err := applier.Apply(context.Background(), first); err != nil {
		t.Fatal(err)
	}

	if err := applier.Apply(context.Background(), second); !errors.Is(err, applyErr) {
		t.Fatalf("Apply() error=%v, want %v", err, applyErr)
	}

	if got := applier.Revision(); got != 1 {
		t.Fatalf("revision=%d, want 1", got)
	}

	if !strings.Contains(scripts[1], "policy revision=2") {
		t.Fatalf("second script=%q", scripts[1])
	}

	if err := applier.Apply(context.Background(), first); !errors.Is(err, ErrRevisionRollback) {
		t.Fatalf("rollback error=%v", err)
	}
}

func TestPreparedPolicyRejectsForeignOwnerAndRetriesAfterGuard(t *testing.T) {
	ctx := context.Background()
	var live string
	a := NewApplierWithRunner(
		"wg0",
		nil,
		func(_ context.Context, s string) error { live = s; return nil },
	)
	b := NewApplierWithRunner(
		"wg1",
		nil,
		func(context.Context, string) error { t.Fatal("foreign commit mutated firewall"); return nil },
	)
	value := acl.Snapshot{Revision: 1, DefaultAction: acl.ActionDeny}

	prepared, err := a.Prepare(nil, value)

	if err != nil || live != "" {
		t.Fatalf("prepare mutated kernel: %v %s", err, live)
	}

	if err := b.Commit(ctx, prepared); err == nil {
		t.Fatal("foreign owner accepted staged policy")
	}

	if err := a.Guard(ctx); err != nil {
		t.Fatal(err)
	}

	if a.Revision() != 0 {
		t.Fatal("guard advanced applied revision")
	}

	if err := a.Commit(ctx, prepared); err != nil {
		t.Fatal(err)
	}

	if err := a.Guard(ctx); err != nil {
		t.Fatal(err)
	}

	if err := a.Commit(ctx, prepared); err != nil {
		t.Fatalf("same committed revision could not release retry guard: %v", err)
	}

	if a.Revision() != 1 || !strings.Contains(live, "revision=1") {
		t.Fatal("commit did not converge")
	}
}
