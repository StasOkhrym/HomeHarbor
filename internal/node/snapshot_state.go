package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

const maxSnapshotEnvelopeBytes = 64 << 10

// ErrSnapshotState is terminal for the reconnect loop: retrying networking
// cannot repair an invalid checkpoint or make an uncertain fsync durable.
var ErrSnapshotState = errors.New("snapshot checkpoint unavailable or invalid")

func loadSnapshotState(
	path string,
	root ed25519.PublicKey,
	networkID string,
) (snapshot.Envelope, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return snapshot.Envelope{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return snapshot.Envelope{}, errors.New("snapshot checkpoint must be a regular 0600 file")
	}

	file, err := os.Open(path)
	if err != nil {
		return snapshot.Envelope{}, err
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotEnvelopeBytes+1))
	if err != nil {
		return snapshot.Envelope{}, err
	}
	if len(data) > maxSnapshotEnvelopeBytes {
		return snapshot.Envelope{}, errors.New("snapshot checkpoint exceeds envelope limit")
	}

	var envelope snapshot.Envelope

	if err := json.Unmarshal(data, &envelope); err != nil {
		return snapshot.Envelope{}, err
	}

	if _, err := snapshot.Verify(envelope, root, networkID); err != nil {
		return snapshot.Envelope{}, err
	}

	return envelope, nil
}

func restoreSnapshotCursor(
	ctx context.Context,
	cfg CoordinationConfig,
	applier SnapshotApplier,
) (coordinationCursor, error) {
	if cfg.StatePath == "" {
		return coordinationCursor{}, nil
	}
	envelope, err := loadSnapshotState(cfg.StatePath, cfg.RootPublicKey, cfg.NetworkID)
	if errors.Is(err, os.ErrNotExist) {
		return coordinationCursor{}, nil
	}
	if err != nil {
		return coordinationCursor{}, fmt.Errorf("%w: load: %w", ErrSnapshotState, err)
	}
	if applier == nil {
		return coordinationCursor{}, errors.New("snapshot applier is required")
	}
	value, err := snapshot.Verify(envelope, cfg.RootPublicKey, cfg.NetworkID)
	if err != nil {
		return coordinationCursor{}, fmt.Errorf("%w: verify: %w", ErrSnapshotState, err)
	}
	if deferred, ok := applier.(SnapshotRestoreVerifier); ok {
		if err := deferred.VerifyRestore(ctx, envelope, value); err != nil {
			return coordinationCursor{}, fmt.Errorf(
				"%w: verify deferred restore: %w",
				ErrSnapshotState,
				err,
			)
		}
		return coordinationCursor{
			revision:   value.Revision,
			hash:       bytes.Clone(envelope.Hash),
			needsApply: true,
		}, nil
	}
	// Reconstruct local kernel/resolver state on process restart. A checkpoint
	// proves the previously applied target; it does not prove today's kernel.
	if err := applyVerifiedSnapshot(ctx, applier, envelope, value); err != nil {
		return coordinationCursor{}, fmt.Errorf("restore applied snapshot: %w", err)
	}
	return coordinationCursor{revision: value.Revision, hash: bytes.Clone(envelope.Hash)}, nil
}

type preparedSnapshotState struct{ path, temporary string }

// Prepare and fsync the replacement before touching kernel state. Commit is
// delayed until Apply succeeds so the checkpoint never claims a failed apply.
func prepareSnapshotState(path string, envelope snapshot.Envelope) (*preparedSnapshotState, error) {
	if path == "" {
		return nil, nil
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSnapshotEnvelopeBytes {
		return nil, errors.New("snapshot checkpoint exceeds envelope limit")
	}

	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("snapshot checkpoint target is not a regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return nil, err
	}

	prepared := &preparedSnapshotState{path: path, temporary: file.Name()}
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			prepared.abort()
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return nil, err
	}

	if _, err := file.Write(data); err != nil {
		return nil, err
	}

	if err := file.Sync(); err != nil {
		return nil, err
	}

	if err := file.Close(); err != nil {
		return nil, err
	}

	failed = false

	return prepared, nil
}

func (p *preparedSnapshotState) abort() {
	if p != nil && p.temporary != "" {
		_ = os.Remove(p.temporary)
	}
}

func (p *preparedSnapshotState) commit() error {
	if p == nil {
		return nil
	}

	if err := os.Rename(p.temporary, p.path); err != nil {
		return err
	}

	p.temporary = ""

	dir, err := os.Open(filepath.Dir(p.path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()

	return dir.Sync()
}

func persistSnapshotState(path string, envelope snapshot.Envelope) error {
	p, err := prepareSnapshotState(path, envelope)
	if err != nil {
		return err
	}
	defer p.abort()
	return p.commit()
}
