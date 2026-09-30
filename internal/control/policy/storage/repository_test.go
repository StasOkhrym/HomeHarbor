package storage_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
	policypg "github.com/sokhrym/go-tunnels/internal/control/policy/storage"
	"github.com/sokhrym/go-tunnels/internal/testutil"
)

func TestPostgresPolicyRevisionAndRulesRollbackTogether(t *testing.T) {
	pool := testutil.Postgres(t)
	testutil.Device(t, pool, "client", "client")
	repo := policypg.New(pool)
	ctx := context.Background()
	initial, err := repo.Latest(ctx)
	if err != nil || initial.DefaultAction != policy.ActionDeny || initial.Revision != 0 {
		t.Fatalf("initial policy=%#v %v", initial, err)
	}
	rule := policy.Rule{ID: "https", SourceDeviceID: "client", Destination: netip.MustParsePrefix("192.168.50.2/32"), Protocol: policy.ProtocolTCP, PortFrom: 443, PortTo: 443}
	first, err := repo.Replace(ctx, []policy.Rule{rule}, policy.Compiler{})
	if err != nil || first.Revision != 1 {
		t.Fatalf("first revision=%#v %v", first, err)
	}
	rule.SourceDeviceID = "missing"
	if _, err := repo.Replace(ctx, []policy.Rule{rule}, policy.Compiler{}); err == nil {
		t.Fatal("invalid foreign key accepted")
	}
	latest, err := repo.Latest(ctx)
	if err != nil || latest.Revision != 1 || len(latest.Rules) != 1 || latest.Rules[0].SourceDeviceID != "client" {
		t.Fatalf("failed replacement mutated history: %#v %v", latest, err)
	}
	var source string
	if err := pool.QueryRow(ctx, `SELECT source_device_id FROM policy_rules WHERE id='https'`).Scan(&source); err != nil || source != "client" {
		t.Fatalf("current rules lost: %s %v", source, err)
	}
	next, err := repo.Replace(ctx, nil, policy.Compiler{})
	if err != nil || next.Revision != 2 || len(next.Rules) != 0 {
		t.Fatalf("empty deny revision=%#v %v", next, err)
	}
}
