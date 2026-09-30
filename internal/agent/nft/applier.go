package nft

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"

	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

var ErrRevisionRollback = errors.New("nftables policy revision rollback")

type scriptRunner func(context.Context, string) error

// Applier owns the last accepted policy revision for one gateway interface.
// Compile and nft's transactional file application happen before current state
// is updated, so a rejected or failed script leaves the prior policy active.
type Applier struct {
	mu            sync.Mutex
	interfaceName string
	peers         map[string]netip.Prefix
	run           scriptRunner
	revision      uint64
}

func NewApplier(interfaceName string, peers map[string]netip.Prefix) *Applier {
	return &Applier{interfaceName: interfaceName, peers: clonePeers(peers), run: applyScript}
}

// Apply compiles and atomically installs a newer default-deny policy. The
// revision check prevents a delayed control update from weakening a gateway.
func (a *Applier) Apply(ctx context.Context, snapshot policy.Snapshot) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if snapshot.Revision <= a.revision {
		return ErrRevisionRollback
	}
	script, err := Compile(a.interfaceName, a.peers, snapshot)
	if err != nil {
		return err
	}
	if err := a.run(ctx, script); err != nil {
		return fmt.Errorf("apply nftables policy revision %d: %w", snapshot.Revision, err)
	}
	a.revision = snapshot.Revision
	return nil
}

func (a *Applier) Revision() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.revision
}

// UpdatePeers replaces the source-address map used by the next policy
// compilation. It does not touch nftables; Apply remains the transaction
// boundary that can reject the complete update without changing live rules.
func (a *Applier) UpdatePeers(peers map[string]netip.Prefix) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.peers = clonePeers(peers)
}

func clonePeers(peers map[string]netip.Prefix) map[string]netip.Prefix {
	copy := make(map[string]netip.Prefix, len(peers))
	for id, prefix := range peers {
		copy[id] = prefix
	}

	return copy
}

func applyScript(ctx context.Context, script string) error {
	command := exec.CommandContext(ctx, "nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
