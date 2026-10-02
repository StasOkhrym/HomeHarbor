package companion

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/httpapi"
)

func companionHTTPFixture(
	t *testing.T,
	resources httpapi.ResourceDependencies,
	root ed25519.PublicKey,
	auth httpapi.Authorizer,
) http.Handler {
	t.Helper()

	server, err := httpapi.NewServer(httpapi.Dependencies{
		Resources: resources,
		Security: httpapi.SecurityDependencies{
			Authorizer:    auth,
			RootPublicKey: root,
			Challenges: &companionTestChallenges{
				values: make(map[string]companionTestChallenge),
			},
			CompanionTTL:  time.Minute,
			APILimiter:    httpapi.NewRateLimiter(120, time.Minute, nil),
			AuthLimiter:   httpapi.NewRateLimiter(5, time.Minute, nil),
			DeviceLimiter: httpapi.NewRateLimiter(10, time.Minute, nil),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	return server.Handler()
}

type (
	companionTestChallenge struct {
		value   []byte
		expires time.Time
	}
	companionTestChallenges struct {
		mu     sync.Mutex
		values map[string]companionTestChallenge
	}
)

func (s *companionTestChallenges) PutChallenge(
	_ context.Context,
	purpose, key string,
	value []byte,
	ttl time.Duration,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values[purpose+key] = companionTestChallenge{
		value:   append([]byte(nil), value...),
		expires: time.Now().Add(ttl),
	}

	return nil
}

func (s *companionTestChallenges) ConsumeChallenge(
	_ context.Context,
	purpose, key string,
) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value := s.values[purpose+key]
	delete(s.values, purpose+key)
	if !value.expires.After(time.Now()) {
		return nil, nil
	}

	return value.value, nil
}
