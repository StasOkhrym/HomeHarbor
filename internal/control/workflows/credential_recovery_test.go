package workflows

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/platform/redissecurity"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type recoveryDevices struct {
	mu     sync.Mutex
	d      devices.Device
	issued int
}

func (d *recoveryDevices) Device(context.Context, string) (devices.Device, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.d, nil
}

func (d *recoveryDevices) RecoverCredential(
	_ context.Context,
	id, key string,
) (protocol.CredentialLease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.d.Status != devices.StatusActive || d.d.ID != id || d.d.IdentityPublicKey != key {
		return protocol.CredentialLease{}, devices.ErrDeviceNotFound
	}

	d.issued++
	return protocol.CredentialLease{
		DeviceID:   id,
		Credential: "replacement",
		ExpiresAt:  time.Now().Add(time.Minute),
	}, nil
}

type challenges struct {
	mu     sync.Mutex
	values map[string][]byte
}

func (c *challenges) PutChallenge(_ context.Context, p, k string, v []byte, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values[p+k] = v

	return nil
}

func (c *challenges) ConsumeChallenge(_ context.Context, p, k string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	v := c.values[p+k]
	delete(c.values, p+k)
	return v, nil
}

func recoveryFixture(t *testing.T) (*CredentialRecovery, *recoveryDevices, ed25519.PrivateKey) {
	t.Helper()

	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	d := &recoveryDevices{
		d: devices.Device{
			ID:                "device",
			Status:            devices.StatusActive,
			IdentityPublicKey: base64.RawURLEncoding.EncodeToString(pub),
		},
	}

	return NewCredentialRecovery(
		d,
		&challenges{values: map[string][]byte{}},
		"network",
		time.Now,
		rand.Reader,
	), d, key
}

func challengeProof(
	t *testing.T,
	r *CredentialRecovery,
	key ed25519.PrivateKey,
) protocol.CredentialProof {
	t.Helper()

	c, err := r.Challenge(t.Context(), "device")
	if err != nil {
		t.Fatal(err)
	}

	p, err := protocol.SignCredentialProof(c, key)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestRecoveryRequiresActiveDeviceIdentity(t *testing.T) {
	for _, scenario := range []string{"active", "revoked", "wrong key", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			r, d, key := recoveryFixture(t)

			p := challengeProof(t, r, key)
			switch scenario {
			case "revoked":
				d.d.Status = devices.StatusRevoked
			case "wrong key":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)

				d.d.IdentityPublicKey = base64.RawURLEncoding.EncodeToString(pub)
			case "unknown":
				d.d.ID = "other"
			}

			lease, err := r.Recover(t.Context(), p)
			if scenario == "active" {
				if err != nil || lease.DeviceID != "device" {
					t.Fatalf("active recovery failed: %v", err)
				}
			} else if !errors.Is(err, protocol.ErrInvalidCredentialProof) {
				t.Fatalf("expected generic invalid proof: %v", err)
			}
		})
	}
}

func TestRecoveryRejectsWrongNetworkAndExpiredNonce(t *testing.T) {
	for _, kind := range []string{"network", "expired", "future", "tampered"} {
		t.Run(kind, func(t *testing.T) {
			r, _, key := recoveryFixture(t)

			p := challengeProof(t, r, key)
			switch kind {
			case "network":
				p.Challenge.NetworkID = "other"
			case "expired":
				r.now = func() time.Time { return time.Unix(p.Challenge.ExpiresAt, 0) }
			case "future":
				p.Challenge.ExpiresAt += 120
			case "tampered":
				p.Challenge.DeviceID = "other"
			}

			if kind != "expired" {
				p, _ = protocol.SignCredentialProof(p.Challenge, key)
			}

			if _, err := r.Recover(
				t.Context(),
				p,
			); !errors.Is(
				err,
				protocol.ErrInvalidCredentialProof,
			) {
				t.Fatalf("accepted %s: %v", kind, err)
			}
		})
	}
}

func TestRecoveryChallengeConsumedOnceAcrossReplicas(t *testing.T) {
	r, d, key := recoveryFixture(t)
	other := NewCredentialRecovery(d, r.challenges, "network", time.Now, rand.Reader)

	p := challengeProof(t, r, key)
	var successes atomic.Int32
	var group sync.WaitGroup
	for i := range 12 {
		group.Go(func() {
			selected := r
			if i%2 == 1 {
				selected = other
			}

			if _, err := selected.Recover(t.Context(), p); err == nil {
				successes.Add(1)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successful recoveries=%d", successes.Load())
	}
}

func TestRecoveryChallengesDoNotLookUpDevices(t *testing.T) {
	r, _, _ := recoveryFixture(t)
	r.devices = nil
	for _, id := range []string{"device", "unknown"} {
		c, err := r.Challenge(t.Context(), id)

		if err != nil || c.DeviceID != id {
			t.Fatalf("challenge failed for plausible ID: %v", err)
		}
	}
}

func TestRedisRecoveryChallengeConsumedOnceAcrossReplicas(t *testing.T) {
	endpoint := os.Getenv("TEST_REDIS_URL")
	if endpoint == "" {
		t.Skip("TEST_REDIS_URL required")
	}

	options, err := redis.ParseURL(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	one, two := redis.NewClient(options), redis.NewClient(options)
	defer func() { _ = one.Close() }()
	defer func() { _ = two.Close() }()

	prefix := fmt.Sprintf("recovery:%d", time.Now().UnixNano())

	r, d, key := recoveryFixture(t)
	r.challenges = redissecurity.New(one, prefix)
	other := NewCredentialRecovery(
		d,
		redissecurity.New(two, prefix),
		"network",
		time.Now,
		rand.Reader,
	)

	p := challengeProof(t, r, key)
	var successes atomic.Int32
	var group sync.WaitGroup
	for i := range 20 {
		group.Go(func() {
			selected := r
			if i%2 == 1 {
				selected = other
			}

			if _, err := selected.Recover(t.Context(), p); err == nil {
				successes.Add(1)
			}
		})
	}

	group.Wait()

	if successes.Load() != 1 {
		t.Fatalf("successful recoveries=%d", successes.Load())
	}

	fresh := challengeProof(t, other, key)

	if _, err := r.Recover(t.Context(), fresh); err != nil {
		t.Fatalf("fresh challenge did not recover lost response: %v", err)
	}

	// Server-side storage must contain the complete challenge under a distinct purpose.
	c, err := r.Challenge(t.Context(), "device")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := r.challenges.ConsumeChallenge(t.Context(), "credential-recovery", c.Nonce)
	if err != nil {
		t.Fatal(err)
	}

	var stored protocol.CredentialChallenge

	if json.Unmarshal(raw, &stored) != nil || stored != c {
		t.Fatal("challenge storage mismatch")
	}
}
