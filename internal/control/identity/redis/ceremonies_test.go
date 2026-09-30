package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/identity"
)

type failingChallenges struct{}

func (failingChallenges) PutChallenge(context.Context, string, string, []byte, time.Duration) error {
	return errors.New("unavailable")
}

func (failingChallenges) ConsumeChallenge(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("unavailable")
}

func TestCeremonyStoreFailureIsUnavailableNotInvalidProof(t *testing.T) {
	repository := NewCeremonies(failingChallenges{}, time.Now)
	if err := repository.SaveCeremony(t.Context(), identity.Ceremony{ExpiresAt: time.Now().Add(time.Minute)}); !errors.Is(err, identity.ErrSecurityStateUnavailable) {
		t.Fatalf("save error=%v", err)
	}
	if _, err := repository.ConsumeCeremony(t.Context(), [32]byte{}, time.Now()); !errors.Is(err, identity.ErrSecurityStateUnavailable) {
		t.Fatalf("consume error=%v", err)
	}
}
