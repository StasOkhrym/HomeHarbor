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

func TestCompanionDependenciesPreserveConfiguredTTLAndAuthority(t *testing.T) {
	root := make(ed25519.PublicKey, ed25519.PublicKeySize)

	now := time.Unix(1000, 0)
	recorder := &challengeTTLRecorder{}

	deps := explicitTestDependencies()
	deps.Security.RootPublicKey = root
	deps.Security.CompanionTTL = 10 * time.Second
	deps.Security.Challenges = recorder

	server, err := NewServer(deps)
	if err != nil {
		t.Fatal(err)
	}

	_, expiry, err := server.companionChallenges.issue(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}

	if expiry.Sub(now) != 10*time.Second || recorder.ttl != 10*time.Second {
		t.Errorf(
			"issued %v, stored %v; configured TTL/Redis authority lost",
			expiry.Sub(now),
			recorder.ttl,
		)
	}
}
