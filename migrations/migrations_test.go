package migrations

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestConcurrentUpSerializesWithAdvisoryLock(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is required for PostgreSQL migration integration")
	}

	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	start := make(chan struct{})
	errors := make(chan error, 2)
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	for range 2 {
		go func() {
			defer waitGroup.Done()

			<-start
			errors <- Up(context.Background(), pool)
		}()
	}

	close(start)
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := Ready(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
}
