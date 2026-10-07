package policy_test

import (
	"context"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
)

func TestPolicyEmptyDefaultsDeny(t *testing.T) {
	got, err := memorystore.NewRepository().Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if got.DefaultAction != acl.ActionDeny || got.Rules == nil || len(got.Rules) != 0 {
		t.Fatalf("empty policy = %#v", got)
	}
}
