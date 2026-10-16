package node

import (
	"context"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Close runs only after transport workers join. It retires this exclusive
// interface owner's peer set, leaving keys, link and unrelated host state alone.
func (r *SnapshotWireGuardReconciler) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.owned {
		return nil
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	if err := r.apply(r.interfaceName, wgtypes.Config{ReplacePeers: true}); err != nil {
		return err
	}

	r.owned = false
	r.current = nil
	clear(r.endpoints)
	return nil
}

func (r *ClientReconciler) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.routes.reconcile(ctx, r.interfaceName, nil, func() error { return nil })
}

func (r *GatewayReconciler) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.policies.Guard(ctx); err != nil {
		return err
	}

	r.guarded, r.staged = true, false

	return r.routes.reconcile(ctx, r.interfaceName, nil, func() error { return nil })
}
