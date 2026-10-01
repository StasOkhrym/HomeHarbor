package policy

import (
	"context"
	"errors"
	"testing"
)

func TestConfirmedReplacementRejectsStaleRevision(t *testing.T) {
	service := NewService(NewMemoryStore(), Compiler{})
	ctx := context.Background()
	if _, err := service.ReplaceIfRevision(ctx, 0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReplaceIfRevision(ctx, 0, nil); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale preview error=%v", err)
	}
	value, _ := service.Latest(ctx)
	if value.Revision != 1 {
		t.Fatal("stale confirmation created a revision")
	}
}
