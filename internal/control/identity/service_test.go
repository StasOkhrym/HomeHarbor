package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateRecoveryCodesStoresOnlyHashes(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(
		store,
		store,
		func() time.Time { return time.Unix(100, 0) },
		&sequenceReader{next: 'r'},
	)

	codes, err := service.GenerateRecoveryCodes(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 {
		t.Fatalf("codes = %d", len(codes))
	}
	for _, code := range codes {
		if code == "" {
			t.Fatal("empty recovery code")
		}
		if store.ContainsPlaintext(code) {
			t.Fatal("store contains plaintext recovery code")
		}
	}
}

func TestRecoveryCodeCanBeConsumedOnlyOnceConcurrently(t *testing.T) {
	store := NewMemoryStore()
	service := NewService(
		store,
		store,
		func() time.Time { return time.Unix(100, 0) },
		&sequenceReader{next: 'c'},
	)
	codes, err := service.GenerateRecoveryCodes(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int32
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			if service.ConsumeRecoveryCode(context.Background(), codes[0]) == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d", successes.Load())
	}
}

func TestSessionExpiresAndCanBeRevoked(t *testing.T) {
	store := NewMemoryStore()
	now := time.Unix(100, 0)
	service := NewService(store, store, func() time.Time { return now }, &sequenceReader{next: 's'})

	issued, err := service.CreateSession(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ValidateSession(context.Background(), issued.Token); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if _, err = service.ValidateSession(
		context.Background(),
		issued.Token,
	); !errors.Is(
		err,
		ErrInvalidCredential,
	) {
		t.Fatalf("expired error = %v", err)
	}

	now = time.Unix(100, 0)
	issued, err = service.CreateSession(context.Background(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.RevokeSession(context.Background(), issued.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = service.ValidateSession(
		context.Background(),
		issued.Token,
	); !errors.Is(
		err,
		ErrInvalidCredential,
	) {
		t.Fatalf("revoked error = %v", err)
	}
}

func TestInvalidSessionTokenUsesGenericError(t *testing.T) {
	service := NewService(NewMemoryStore(), NewMemoryStore(), time.Now, &sequenceReader{next: 'x'})
	if _, err := service.ValidateSession(
		context.Background(),
		"unknown",
	); !errors.Is(
		err,
		ErrInvalidCredential,
	) {
		t.Fatalf("error = %v", err)
	}
}

type unavailableSessions struct{ *MemoryStore }

func (unavailableSessions) Session(context.Context, [32]byte) (Session, error) {
	return Session{}, ErrSecurityStateUnavailable
}

func (unavailableSessions) RevokeSession(context.Context, [32]byte, time.Time) error {
	return ErrSecurityStateUnavailable
}

func TestSessionStoreOutageIsNotAnInvalidCredential(t *testing.T) {
	store := unavailableSessions{NewMemoryStore()}
	service := NewService(store, store, time.Now, nil)
	if _, err := service.ValidateSession(
		context.Background(),
		"opaque",
	); !errors.Is(
		err,
		ErrSecurityStateUnavailable,
	) {
		t.Fatalf("lookup outage was hidden: %v", err)
	}
	if err := service.RevokeSession(
		context.Background(),
		"opaque",
	); !errors.Is(
		err,
		ErrSecurityStateUnavailable,
	) {
		t.Fatalf("revoke outage was hidden: %v", err)
	}
}

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *sequenceReader) Read(buffer []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()

	for index := range buffer {
		buffer[index] = reader.next
	}

	reader.next++
	return len(buffer), nil
}
