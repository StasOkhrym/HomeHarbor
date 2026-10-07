package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	domainpkg "github.com/StasOkhrym/homeharbor/internal/control/policy"
	memorystore "github.com/StasOkhrym/homeharbor/internal/testutil/control/policy"
)

func TestConfirmedReplacementRejectsStaleRevision(t *testing.T) {
	service := domainpkg.NewService(memorystore.NewRepository(), acl.Compiler{})
	ctx := context.Background()

	if _, err := service.ReplaceIfRevision(ctx, 0, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := service.ReplaceIfRevision(
		ctx,
		0,
		nil,
	); !errors.Is(
		err,
		domainpkg.ErrRevisionConflict,
	) {
		t.Fatalf("stale preview error=%v", err)
	}

	value, _ := service.Latest(ctx)

	if value.Revision != 1 {
		t.Fatal("stale confirmation created a revision")
	}
}
