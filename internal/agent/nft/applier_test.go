package nft

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

func TestApplierKeepsLastRevisionWhenNftRejectsUpdate(t *testing.T) {
	applier := NewApplier("gt0", map[string]netip.Prefix{"client": netip.MustParsePrefix("100.64.0.2/32")})
	var scripts []string
	applyErr := errors.New("nft syntax error")
	applier.run = func(_ context.Context, script string) error {
		scripts = append(scripts, script)
		if len(scripts) == 2 {
			return applyErr
		}
		return nil
	}
	first := policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{ID: "allow-http", SourceDeviceID: "client", Destination: netip.MustParsePrefix("192.168.1.0/24"), Protocol: policy.ProtocolTCP, PortFrom: 443, PortTo: 443}}}
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
