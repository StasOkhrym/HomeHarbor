package snapshots

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

type racingRepository struct {
	*MemoryStore
	reads atomic.Int32
	ready chan struct{}
}

func (r *racingRepository) Latest(ctx context.Context, networkID string) (snapshot.Envelope, error) {
	envelope, err := r.MemoryStore.Latest(ctx, networkID)
	if r.reads.Add(1) == 2 {
		close(r.ready)
	}
	<-r.ready
	return envelope, err
}

func TestPublishAcrossServiceInstancesHasOneWinner(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 1}, private, "root")
	if err != nil {
		t.Fatal(err)
	}
	repository := &racingRepository{MemoryStore: NewMemoryStore(), ready: make(chan struct{})}
	var group sync.WaitGroup
	var successes atomic.Int32
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			err := NewService(repository, public, "home").Publish(context.Background(), first)
			if err == nil {
				successes.Add(1)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 {
		t.Fatalf("append winners = %d, want one", successes.Load())
	}
}

func TestPublishRejectsSkippedGenesis(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := snapshot.Sign(snapshot.NetworkSnapshot{NetworkID: "home", Revision: 7}, private, "root")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewService(
		NewMemoryStore(),
		public,
		"home",
	).Publish(context.Background(), envelope); !errors.Is(
		err,
		snapshot.ErrRevisionGap,
	) {
		t.Fatalf("skipped genesis = %v", err)
	}
}

func TestHistoryIsPagedVerifiedAndNetworkScoped(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryStore()
	service := NewService(repository, public, "home")
	var previous []byte
	for revision := uint64(1); revision <= 5; revision++ {
		envelope, err := snapshot.Sign(
			snapshot.NetworkSnapshot{NetworkID: "home", Revision: revision, PreviousHash: previous},
			private,
			"root",
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Publish(context.Background(), envelope); err != nil {
			t.Fatal(err)
		}
		previous = envelope.Hash
	}
	page, err := service.History(context.Background(), 2, 2)
	if err != nil || len(page) != 2 {
		t.Fatalf("page len=%d err=%v", len(page), err)
	}
	for i, envelope := range page {
		value, _ := snapshot.Decode(envelope)
		if value.Revision != uint64(i+3) {
			t.Fatalf("page revision=%d", value.Revision)
		}
	}
	page[0].Hash[0] ^= 1
	if _, err := service.History(context.Background(), 2, 2); err != nil {
		t.Fatalf("caller mutated persisted history: %v", err)
	}
	if _, err := service.History(context.Background(), 6, 2); !errors.Is(err, ErrHistoryCursor) {
		t.Fatalf("unknown cursor: %v", err)
	}
	if _, err := service.History(context.Background(), 0, MaxHistoryPageSize+1); !errors.Is(err, ErrHistoryCursor) {
		t.Fatalf("unbounded page: %v", err)
	}
	other := NewService(repository, public, "other")
	page, err = other.History(context.Background(), 0, 2)
	if err != nil || len(page) != 0 {
		t.Fatalf("other history=%v err=%v", page, err)
	}
	repository.mu.Lock()
	repository.history["home"] = append(repository.history["home"][:2], repository.history["home"][3:]...)
	repository.mu.Unlock()
	if _, err := service.History(context.Background(), 1, 4); !errors.Is(err, snapshot.ErrRevisionGap) {
		t.Fatalf("missing revision: %v", err)
	}
}
