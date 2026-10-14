package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()

	// testing creates its numbered directory with 0777 before applying umask.
	// State fixtures explicitly own their permissions, even with umask 0002.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}

	return path
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(privateTestDir(t), "state.json"))
	if e != nil {
		t.Fatal(e)
	}

	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSecondOwnerRejected(t *testing.T) {
	s := openTestStore(t)

	other, e := Open(s.path)
	if e == nil {
		_ = other.Close()

		t.Fatal("second owner acquired state")
	}
}

func TestReplaceSyncFailurePreservesOldState(t *testing.T) {
	s := openTestStore(t)

	if e := s.Replace([]byte("old")); e != nil {
		t.Fatal(e)
	}

	failure := errors.New("file sync failed")
	s.fileSync = func(*os.File) error { return failure }

	if e := s.Replace([]byte("new")); !errors.Is(e, failure) {
		t.Fatalf("error = %v", e)
	}

	b, e := s.Read()

	if e != nil || string(b) != "old" {
		t.Fatalf("state = %q, %v", b, e)
	}
}

func TestDirectorySyncFailureReportsUncertainDurability(t *testing.T) {
	s := openTestStore(t)

	if e := s.Replace([]byte("old")); e != nil {
		t.Fatal(e)
	}

	failure := errors.New("directory sync failed")
	s.dirSync = func(*os.File) error { return failure }

	e := s.Replace([]byte("new"))

	if !errors.Is(e, failure) || !errors.Is(e, ErrDurabilityUncertain) {
		t.Fatalf("error = %v", e)
	}

	b, e := s.Read()

	if e != nil || string(b) != "new" {
		t.Fatalf("rename did not publish bytes: %q, %v", b, e)
	}
}

func TestPrivateMode(t *testing.T) {
	s := openTestStore(t)

	if e := s.Replace([]byte("secret")); e != nil {
		t.Fatal(e)
	}

	for _, p := range []string{s.path, s.path + ".lock"} {
		i, e := os.Stat(p)
		if e != nil {
			t.Fatal(e)
		}

		if i.Mode().Perm() != 0o600 || !i.Mode().IsRegular() {
			t.Fatalf("unsafe mode %v", i.Mode())
		}
	}
}

func TestRejectSymlink(t *testing.T) {
	dir := privateTestDir(t)
	target := filepath.Join(dir, "target")

	if e := os.WriteFile(target, []byte("secret"), 0o600); e != nil {
		t.Fatal(e)
	}

	path := filepath.Join(dir, "state")

	if e := os.Symlink(target, path); e != nil {
		t.Fatal(e)
	}

	s, e := Open(path)
	if e == nil {
		_ = s.Close()

		t.Fatal("symlink accepted")
	}
}

func TestRejectUnsafePaths(t *testing.T) {
	for _, kind := range []string{"parent symlink", "writable parent", "lock symlink", "public state", "hardlinked state"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDir(t)
			path := filepath.Join(dir, "state.json")
			switch kind {
			case "parent symlink":
				link := filepath.Join(privateTestDir(t), "link")

				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}

				path = filepath.Join(link, "state.json")
			case "writable parent":
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			case "lock symlink":
				target := filepath.Join(dir, "other")

				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}

				if err := os.Symlink(target, path+".lock"); err != nil {
					t.Fatal(err)
				}
			case "public state":
				if err := os.WriteFile(path, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlinked state":
				target := filepath.Join(dir, "other")

				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}

				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			}

			s, err := Open(path)
			if err == nil {
				_ = s.Close()

				t.Fatal("unsafe path accepted")
			}
		})
	}
}

func TestReplaceUsesOwnedDirectory(t *testing.T) {
	root := privateTestDir(t)
	dir := filepath.Join(root, "owned")
	path := filepath.Join(dir, "state.json")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()

	moved := filepath.Join(root, "moved")

	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := s.Replace([]byte("owned bytes")); err != nil {
		t.Fatal(err)
	}

	bytes, err := os.ReadFile(filepath.Join(moved, "state.json"))

	if err != nil || string(bytes) != "owned bytes" {
		t.Fatalf("owned directory = %q, %v", bytes, err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("replacement escaped owned directory: %v", err)
	}
}

func TestCloseReleasesOwnerAndRejectsFurtherIO(t *testing.T) {
	s := openTestStore(t)

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Read(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after close: %v", err)
	}

	if err := s.Replace(nil); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Replace after close: %v", err)
	}

	other, err := Open(s.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := other.Close(); err != nil {
			t.Error(err)
		}
	}()
}
