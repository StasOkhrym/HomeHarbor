package node

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type compositeOwner struct {
	calls                  *[]string
	failPrepare, failApply bool
}

func (o *compositeOwner) Prepare(context.Context, snapshot.NetworkSnapshot) error {
	*o.calls = append(*o.calls, "validate-peer")
	if o.failPrepare {
		return errors.New("invalid peer")
	}

	return nil
}

func (o *compositeOwner) Apply(context.Context, snapshot.NetworkSnapshot) error {
	*o.calls = append(*o.calls, "apply-peer")
	if o.failApply {
		return errors.New("kernel failure")
	}

	return nil
}

type compositeGuard struct {
	calls    *[]string
	denied   bool
	revision uint64
}

func (g *compositeGuard) Apply(ctx context.Context, v snapshot.NetworkSnapshot) error {
	if err := g.Prepare(ctx, v); err != nil {
		return err
	}

	if err := g.Guard(ctx, v); err != nil {
		return err
	}

	if err := g.ApplyPrepared(ctx, v); err != nil {
		return err
	}

	return g.Commit(ctx, v)
}

func (g *compositeGuard) Prepare(context.Context, snapshot.NetworkSnapshot) error {
	*g.calls = append(*g.calls, "validate-gateway")
	return nil
}

func (g *compositeGuard) Guard(context.Context, snapshot.NetworkSnapshot) error {
	*g.calls = append(*g.calls, "deny")
	g.denied = true

	return nil
}

func (g *compositeGuard) ApplyPrepared(context.Context, snapshot.NetworkSnapshot) error {
	*g.calls = append(*g.calls, "apply-gateway")
	return nil
}

func (g *compositeGuard) Commit(_ context.Context, v snapshot.NetworkSnapshot) error {
	*g.calls = append(*g.calls, "commit")
	g.denied = false
	g.revision = v.Revision

	return nil
}

func TestCompositePreparesEveryOwnerBeforeKernelMutation(t *testing.T) {
	var calls []string
	guard := &compositeGuard{calls: &calls}
	peer := &compositeOwner{calls: &calls, failPrepare: true}
	value := snapshot.NetworkSnapshot{Revision: 2}
	if err := NewCompositeSnapshotApplier(guard, peer).Apply(context.Background(), value); err == nil {
		t.Fatal("accepted invalid peer")
	}
	if !reflect.DeepEqual(calls, []string{"validate-gateway", "validate-peer"}) || guard.denied {
		t.Fatalf("validation mutated kernel: calls=%v guard=%v", calls, guard.denied)
	}
}

func TestCompositeFailureLeavesGuardUntilCompleteRetry(t *testing.T) {
	var calls []string
	guard := &compositeGuard{calls: &calls, revision: 1}
	peer := &compositeOwner{calls: &calls, failApply: true}
	app := NewCompositeSnapshotApplier(guard, peer)
	value := snapshot.NetworkSnapshot{Revision: 2}
	if err := app.Apply(context.Background(), value); err == nil {
		t.Fatal("hidden kernel failure")
	}
	if !guard.denied || guard.revision != 1 {
		t.Fatalf("failed apply exposed mixed state: %#v", guard)
	}
	peer.failApply = false
	calls = nil
	if err := app.Apply(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if guard.denied || guard.revision != 2 {
		t.Fatalf("retry did not commit: %#v", guard)
	}
	if !reflect.DeepEqual(
		calls,
		[]string{"validate-gateway", "validate-peer", "deny", "apply-gateway", "apply-peer", "commit"},
	) {
		t.Fatalf("unsafe order: %v", calls)
	}
}
