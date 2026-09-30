// Package redis implements ephemeral identity ceremonies and browser sessions.
package redis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/identity"
	"github.com/sokhrym/go-tunnels/internal/platform/redissecurity"
)

// Challenges is the adapter's narrow dependency on shared security storage.
type Challenges interface {
	PutChallenge(context.Context, string, string, []byte, time.Duration) error
	ConsumeChallenge(context.Context, string, string) ([]byte, error)
}

type Ceremonies struct {
	store Challenges
	now   func() time.Time
}

func NewCeremonies(store Challenges, now func() time.Time) *Ceremonies {
	return &Ceremonies{store: store, now: now}
}

func (c *Ceremonies) SaveCeremony(ctx context.Context, value identity.Ceremony) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := c.store.PutChallenge(ctx, "webauthn", hex.EncodeToString(value.IDHash[:]), payload, value.ExpiresAt.Sub(c.now())); err != nil {
		return fmt.Errorf("%w: save ceremony", identity.ErrSecurityStateUnavailable)
	}
	return nil
}

func (c *Ceremonies) ConsumeCeremony(ctx context.Context, hash [32]byte, now time.Time) (identity.Ceremony, error) {
	payload, err := c.store.ConsumeChallenge(ctx, "webauthn", hex.EncodeToString(hash[:]))
	if errors.Is(err, redissecurity.ErrChallengeMissing) {
		return identity.Ceremony{}, identity.ErrInvalidCeremony
	}
	if err != nil {
		return identity.Ceremony{}, fmt.Errorf("%w: consume ceremony", identity.ErrSecurityStateUnavailable)
	}
	var value identity.Ceremony
	if err := json.Unmarshal(payload, &value); err != nil || value.IDHash != hash || !now.Before(value.ExpiresAt) {
		return identity.Ceremony{}, identity.ErrInvalidCeremony
	}
	return value, nil
}

var _ identity.CeremonyRepository = (*Ceremonies)(nil)
