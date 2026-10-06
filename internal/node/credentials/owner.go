// Package credentials owns durably published device leases.
package credentials

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type (
	LeaseSource interface {
		Current(context.Context) (protocol.CredentialLease, error)
	}
	// Clock permits deterministic renewal tests without changing server-issued expiry.
	Clock interface {
		Now() time.Time
		After(time.Duration) <-chan time.Time
	}
	Config struct {
		Initial          protocol.CredentialLease
		Clock            Clock
		Rotate           func(context.Context, protocol.CredentialLease) (protocol.CredentialLease, error)
		Recover          func(context.Context) (protocol.CredentialLease, error)
		Save             func(context.Context, protocol.CredentialLease) error
		OperationTimeout time.Duration
	}
)
type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Owner serializes startup, refresh, recovery and durable publication. The first
// Current renews persisted credentials; subsequent calls never perform I/O.
// Run is the sole retry/refresh worker and must be joined before closing Save's store.
type Owner struct {
	cfg         Config
	gate        chan struct{}
	running     atomic.Bool
	initialized bool
	current     protocol.CredentialLease
	next        time.Time
}

func New(cfg Config) *Owner {
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}

	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = 10 * time.Second
	}

	return &Owner{cfg: cfg, gate: make(chan struct{}, 1)}
}

func (o *Owner) lock(ctx context.Context) error {
	select {
	case o.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			o.unlock()
			return err
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (o *Owner) unlock() { <-o.gate }
func (o *Owner) Current(ctx context.Context) (protocol.CredentialLease, error) {
	if err := o.lock(ctx); err != nil {
		return protocol.CredentialLease{}, err
	}
	defer o.unlock()

	if !o.initialized {
		o.initialized = true

		if err := o.refresh(ctx, o.cfg.Initial); err != nil {
			return protocol.CredentialLease{}, err
		}
	}

	if o.current.Credential == "" || !o.current.ExpiresAt.After(o.cfg.Clock.Now()) {
		return protocol.CredentialLease{}, errors.New("credential lease unavailable")
	}

	return o.current, nil
}

func (o *Owner) refresh(ctx context.Context, previous protocol.CredentialLease) error {
	// A failed rotation may have committed remotely. Never reuse the old bearer.
	o.current = protocol.CredentialLease{}
	o.next = o.cfg.Clock.Now().Add(time.Second)
	if o.cfg.Rotate == nil || o.cfg.Recover == nil || o.cfg.Save == nil {
		return errors.New("credential owner dependencies required")
	}

	var next protocol.CredentialLease
	var err error
	if previous.Credential != "" && previous.ExpiresAt.After(o.cfg.Clock.Now()) {
		operation, cancel := context.WithTimeout(
			ctx,
			min(o.cfg.OperationTimeout, previous.ExpiresAt.Sub(o.cfg.Clock.Now())),
		)
		next, err = o.cfg.Rotate(operation, previous)
		cancel()
	} else {
		err = errors.New("credential requires identity recovery")
	}

	if err != nil {
		operation, cancel := context.WithTimeout(ctx, o.cfg.OperationTimeout)
		next, err = o.cfg.Recover(operation)
		cancel()
	}

	if err != nil {
		return err
	}

	received := o.cfg.Clock.Now()
	if next.DeviceID != o.cfg.Initial.DeviceID || next.Credential == "" ||
		!next.ExpiresAt.After(received) {
		return errors.New("invalid credential lease")
	}

	operation, cancel := context.WithTimeout(ctx, o.cfg.OperationTimeout)
	err = o.cfg.Save(operation, next)
	cancel()
	if err != nil {
		return err
	}
	if !next.ExpiresAt.After(o.cfg.Clock.Now()) {
		return errors.New("credential expired during durable save")
	}

	o.current = next
	o.next = received.Add(next.ExpiresAt.Sub(received) * 4 / 5)

	return nil
}

func (o *Owner) Run(ctx context.Context) error {
	if !o.running.CompareAndSwap(false, true) {
		return errors.New("credential owner already running")
	}
	defer o.running.Store(false)

	for {
		if err := o.lock(ctx); err != nil {
			return nil
		}

		if !o.initialized {
			o.initialized = true
			_ = o.refresh(ctx, o.cfg.Initial)
		} else if !o.next.After(o.cfg.Clock.Now()) {
			_ = o.refresh(ctx, o.current)
		}

		delay := max(o.next.Sub(o.cfg.Clock.Now()), time.Millisecond)
		o.unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-o.cfg.Clock.After(delay):
		}
	}
}
