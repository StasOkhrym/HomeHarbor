package storage_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	policypg "github.com/StasOkhrym/homeharbor/internal/control/policy/storage"
	"github.com/StasOkhrym/homeharbor/internal/testutil"
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
	rule := policy.Rule{
		ID:             "https",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       443,
		PortTo:         443,
	}
	first, err := repo.Replace(ctx, []policy.Rule{rule}, policy.Compiler{})
	if err != nil || first.Revision != 1 {
		t.Fatalf("first revision=%#v %v", first, err)
	}
	rule.SourceDeviceID = "missing"
	if _, err := repo.Replace(ctx, []policy.Rule{rule}, policy.Compiler{}); err == nil {
		t.Fatal("invalid foreign key accepted")
	}
	latest, err := repo.Latest(ctx)
	if err != nil || latest.Revision != 1 || len(latest.Rules) != 1 ||
		latest.Rules[0].SourceDeviceID != "client" {
		t.Fatalf("failed replacement mutated history: %#v %v", latest, err)
	}
	var source string
	if err := pool.QueryRow(ctx, `SELECT source_device_id FROM policy_rules WHERE id='https'`).
		Scan(&source); err != nil ||
		source != "client" {
		t.Fatalf("current rules lost: %s %v", source, err)
	}
	next, err := repo.Replace(ctx, nil, policy.Compiler{})
	if err != nil || next.Revision != 2 || len(next.Rules) != 0 {
		t.Fatalf("empty deny revision=%#v %v", next, err)
	}
}

func TestPostgresPolicyConfirmationSerializesWriters(t *testing.T) {
	pool := testutil.Postgres(t)
	repo := policypg.New(pool)
	ctx := context.Background()
	var writers sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		writers.Go(func() {
			_, err := repo.ReplaceIfRevision(ctx, 0, []policy.Rule{}, policy.Compiler{})
			results <- err
		})
	}
	writers.Wait()
	close(results)
	var saved, conflicted int
	for err := range results {
		switch {
		case err == nil:
			saved++
		case errors.Is(err, policy.ErrRevisionConflict):
			conflicted++
		default:
			t.Fatal(err)
		}
	}
	latest, err := repo.Latest(ctx)
	if err != nil || saved != 1 || conflicted != 1 || latest.Revision != 1 {
		t.Fatalf(
			"confirmation results saved=%d conflict=%d revision=%d err=%v",
			saved,
			conflicted,
			latest.Revision,
			err,
		)
	}
}
