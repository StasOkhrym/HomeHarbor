package credentials

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

type (
	fakeClock struct {
		mu     sync.Mutex
		now    time.Time
		timers []fakeTimer
	}
	fakeTimer struct {
		at time.Time
		ch chan time.Time
	}
)

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, fakeTimer{c.now.Add(d), ch})

	return ch
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
	remaining := c.timers[:0]
	for _, t := range c.timers {
		if !t.at.After(c.now) {
			t.ch <- c.now
		} else {
			remaining = append(remaining, t)
		}
	}

	c.timers = remaining
}

func lease(now time.Time, value string) protocol.CredentialLease {
	return protocol.CredentialLease{
		DeviceID:   "device",
		Credential: value,
		ExpiresAt:  now.Add(15 * time.Minute),
	}
}

func fixture() (*fakeClock, Config) {
	c := &fakeClock{now: time.Now()}
	return c, Config{
		Initial: lease(c.Now(), "persisted"),
		Clock:   c,
		Rotate: func(context.Context, protocol.CredentialLease) (protocol.CredentialLease, error) {
			return lease(c.Now(), "rotated"), nil
		},
		Recover: func(context.Context) (protocol.CredentialLease, error) { return lease(c.Now(), "recovered"), nil },
		Save:    func(context.Context, protocol.CredentialLease) error { return nil },
	}
}

func TestOneRotationUnderConcurrentConsumers(t *testing.T) {
	_, cfg := fixture()
	var calls atomic.Int32
	rotate := cfg.Rotate
	cfg.Rotate = func(ctx context.Context, l protocol.CredentialLease) (protocol.CredentialLease, error) {
		calls.Add(1)
		return rotate(ctx, l)
	}
	o := New(cfg)
	var wg sync.WaitGroup
	for range 30 {
		wg.Go(func() {
			l, err := o.Current(context.Background())

			if err != nil || l.Credential != "rotated" {
				t.Errorf("startup lease=%s err=%v", l.Credential, err)
			}
		})
	}

	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("rotation calls=%d want 1", calls.Load())
	}
}

func TestConsumersSeeOnlyDurablySavedLease(t *testing.T) {
	_, cfg := fixture()
	cfg.Save = func(context.Context, protocol.CredentialLease) error { return errors.New("disk sync failed") }
	o := New(cfg)

	if l, err := o.Current(context.Background()); err == nil || l.Credential != "" {
		t.Fatalf("published lease despite failed durable save: %v %v", l, err)
	}
}

func TestLostResponseRecoversWithIdentity(t *testing.T) {
	_, cfg := fixture()
	cfg.Rotate = func(context.Context, protocol.CredentialLease) (protocol.CredentialLease, error) {
		return protocol.CredentialLease{}, errors.New("response lost")
	}
	o := New(cfg)

	l, err := o.Current(context.Background())

	if err != nil || l.Credential != "recovered" {
		t.Fatalf("lost rotation response did not recover: %v %v", l, err)
	}
}

func TestExpiryDoesNotExtendLocally(t *testing.T) {
	c, cfg := fixture()
	o := New(cfg)

	if _, err := o.Current(context.Background()); err != nil {
		t.Fatal(err)
	}

	c.advance(16 * time.Minute)

	if l, err := o.Current(context.Background()); err == nil || l.Credential != "" {
		t.Fatalf("expired lease admitted: %v %v", l, err)
	}
}

func TestRunRenewsBeyondFifteenMinutes(t *testing.T) {
	c, cfg := fixture()
	var calls atomic.Int32
	saved := make(chan protocol.CredentialLease, 4)
	cfg.Rotate = func(context.Context, protocol.CredentialLease) (protocol.CredentialLease, error) {
		return lease(c.Now(), fmt.Sprint(calls.Add(1))), nil
	}
	cfg.Save = func(_ context.Context, l protocol.CredentialLease) error { saved <- l; return nil }
	o := New(cfg)

	if _, err := o.Current(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case <-saved:
	default:
		t.Fatal("startup lease not durably saved")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	defer func() { cancel(); <-done }()

	for range 3 {
		deadline := time.Now().Add(time.Second)
		for {
			c.mu.Lock()
			waiting := len(c.timers) > 0

			c.mu.Unlock()
			if waiting {
				break
			}

			if time.Now().After(deadline) {
				t.Fatal("owner did not schedule renewal")
			}

			time.Sleep(time.Millisecond)
		}

		c.advance(12 * time.Minute)
		select {
		case <-saved:
		case <-time.After(time.Second):
			t.Fatal("owner did not renew at 80 percent")
		}

		l, err := o.Current(ctx)

		if err != nil || !l.ExpiresAt.After(c.Now()) {
			t.Fatalf("invalid renewed lease %v %v", l, err)
		}
	}

	if calls.Load() != 4 {
		t.Fatalf("rotations=%d", calls.Load())
	}
}

func TestUnknownExpiryUsesIdentityRecovery(t *testing.T) {
	_, cfg := fixture()
	cfg.Initial.ExpiresAt = time.Time{}
	cfg.Rotate = func(context.Context, protocol.CredentialLease) (protocol.CredentialLease, error) {
		t.Error("unknown-expiry bearer used for rotation")

		return protocol.CredentialLease{}, errors.New("unexpected rotation")
	}

	current, err := New(cfg).Current(context.Background())

	if err != nil || current.Credential != "recovered" {
		t.Fatalf("unknown expiry did not recover: %v %v", current, err)
	}
}

func TestConcurrentConsumerCannotObservePendingSave(t *testing.T) {
	_, cfg := fixture()
	entered := make(chan struct{})
	release := make(chan struct{})
	cfg.Save = func(context.Context, protocol.CredentialLease) error { close(entered); <-release; return nil }
	o := New(cfg)
	done := make(chan error, 1)
	go func() { _, err := o.Current(context.Background()); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	current, err := o.Current(ctx)

	close(release)

	if err == nil || current.Credential != "" {
		t.Error("pending durable save was exposed to concurrent consumer")
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	current, err = o.Current(context.Background())

	if err != nil || current.Credential != "rotated" {
		t.Fatalf("durable lease not published: %v %v", current, err)
	}
}
