package companion

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileInviteAttemptStorePersistsLockoutWithoutCodeMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invite-attempts.json")
	store, err := NewFileInviteAttemptStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Check("invite-1"); err != nil {
		t.Fatal(err)
	}

	for range MaxInviteCodeAttempts - 1 {
		if err := store.RecordFailure("invite-1"); err != nil {
			t.Fatalf("RecordFailure() error=%v", err)
		}
	}

	if err := store.RecordFailure("invite-1"); !errors.Is(err, ErrInviteAttemptsLocked) {
		t.Fatalf("fifth failure error=%v, want ErrInviteAttemptsLocked", err)
	}

	reloaded, err := NewFileInviteAttemptStore(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := reloaded.Check("invite-1"); !errors.Is(err, ErrInviteAttemptsLocked) {
		t.Fatalf("reloaded Check() error=%v, want ErrInviteAttemptsLocked", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if string(data) == "" || string(data) == "invite-code" {
		t.Fatal("attempt state is empty or contains plaintext code material")
	}
}
