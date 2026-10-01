package httpapi

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

type challengeTTLRecorder struct{ ttl time.Duration }

func (r *challengeTTLRecorder) PutChallenge(
	_ context.Context,
	_, _ string,
	_ []byte,
	ttl time.Duration,
) error {
	r.ttl = ttl
	return nil
}

func (*challengeTTLRecorder) ConsumeChallenge(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func TestCompanionOptionsPreserveConfiguredTTLAndAuthority(t *testing.T) {
	root := make(ed25519.PublicKey, ed25519.PublicKeySize)
	now := time.Unix(1000, 0)
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		recorder := &challengeTTLRecorder{}
		options := []ServerOption{
			WithCompanionTTL(10 * time.Second),
			WithCompanionRootKey(root),
			WithSharedChallenges(recorder),
		}
		server := NewServer(nil, nil, options[order[0]], options[order[1]], options[order[2]])
		_, expiry, err := server.companionChallenges.issue(context.Background(), now)
		if err != nil {
			t.Fatal(err)
		}
		if expiry.Sub(now) != 10*time.Second || recorder.ttl != 10*time.Second {
			t.Errorf(
				"order %v: issued %v, stored %v; configured TTL/Redis authority lost",
				order,
				expiry.Sub(now),
				recorder.ttl,
			)
		}
	}
}
