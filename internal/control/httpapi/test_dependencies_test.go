package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
)

type denyAuthorizer struct{}

func (denyAuthorizer) IsAdmin(context.Context, *http.Request) (bool, error) { return false, nil }

// Test fixtures choose their memory authority explicitly; production NewServer
// has no knowledge of these defaults or permissive peer predicates.
func mustTestServer(service DeviceService, auth Authorizer, deps Dependencies) *Server {
	defaults := explicitTestDependencies()
	deps.Resources.Devices = service
	if auth != nil {
		deps.Security.Authorizer = auth
	} else {
		deps.Security.Authorizer = denyAuthorizer{}
	}
	if deps.Security.APILimiter == nil {
		deps.Security.APILimiter = defaults.Security.APILimiter
	}
	if deps.Security.AuthLimiter == nil {
		deps.Security.AuthLimiter = defaults.Security.AuthLimiter
	}
	if deps.Security.DeviceLimiter == nil {
		deps.Security.DeviceLimiter = defaults.Security.DeviceLimiter
	}
	if len(deps.Security.RootPublicKey) != 0 && deps.Security.Challenges == nil {
		deps.Security.Challenges = &testChallengeRepository{values: make(map[string]testChallenge)}
		deps.Security.CompanionTTL = time.Minute
	}
	if deps.Relay.Issuer != nil && deps.Relay.PeerAuthorizer == nil {
		deps.Relay.PeerAuthorizer = func(context.Context, devices.Device, devices.Device) bool { return true }
	}
	server, err := NewServer(deps)
	if err != nil {
		panic(err)
	}
	return server
}

type testChallenge struct {
	value   []byte
	expires time.Time
}
type testChallengeRepository struct {
	mu     sync.Mutex
	values map[string]testChallenge
}

func (s *testChallengeRepository) PutChallenge(
	_ context.Context,
	purpose, key string,
	value []byte,
	ttl time.Duration,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.values[purpose+key] = testChallenge{
		value:   append([]byte(nil), value...),
		expires: time.Now().Add(ttl),
	}

	return nil
}

func (s *testChallengeRepository) ConsumeChallenge(
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
