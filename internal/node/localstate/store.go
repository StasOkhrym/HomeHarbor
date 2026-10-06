// Package localstate owns private, single-owner byte persistence.
package localstate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// ErrDurabilityUncertain means replacement was published, but directory sync
// failed. Callers must not treat the replacement as a confirmed durable save.
var ErrDurabilityUncertain = errors.New("state replacement durability is uncertain")

type Store struct {
	mu       sync.Mutex
	path     string
	name     string
	parent   *os.File
	lock     *os.File
	closed   bool
	fileSync func(*os.File) error
	dirSync  func(*os.File) error
}

// Open acquires a nonblocking lifetime lock before any state is read or created.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path is required")
	}

	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	parent, err := openParent(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}

	s := &Store{
		path:     absolute,
		name:     filepath.Base(absolute),
		parent:   parent,
		fileSync: (*os.File).Sync,
		dirSync:  (*os.File).Sync,
	}
	lock, err := openPrivate(parent, s.name+".lock", true)
	if err != nil {
		_ = parent.Close()
		return nil, err
	}

	if err = acquireLock(lock); err != nil {
		_ = lock.Close()
		_ = parent.Close()

		return nil, fmt.Errorf("acquire state lock: %w", err)
	}

	s.lock = lock

	// Reject unsafe existing state before returning an owner.
	if file, e := openPrivate(parent, s.name, false); e == nil {
		err = file.Close()
	} else if !errors.Is(e, os.ErrNotExist) {
		err = e
	}

	if err != nil {
		_ = s.Close()
		return nil, err
	}

	return s, nil
}

func (s *Store) Read() (data []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, os.ErrClosed
	}

	file, err := openPrivate(s.parent, s.name, false)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()

	return io.ReadAll(file)
}

func (s *Store) Replace(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return os.ErrClosed
	}

	// Check permissions again in case a file was externally substituted.
	if file, err := openPrivate(s.parent, s.name, false); err == nil {
		if err = file.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	name := ".state-" + hex.EncodeToString(nonce)
	temp, err := createTempAt(s.parent, name)
	if err != nil {
		return err
	}
	defer func() { _ = temp.Close(); _ = removeAt(s.parent, name) }()

	if err = temp.Chmod(0o600); err != nil {
		return err
	}

	if _, err = temp.Write(b); err != nil {
		return err
	}

	if err = s.fileSync(temp); err != nil {
		return fmt.Errorf("sync state file: %w", err)
	}

	if err = temp.Close(); err != nil {
		return err
	}

	if err = renameAt(s.parent, name, s.name); err != nil {
		return err
	}

	if err = s.dirSync(s.parent); err != nil {
		return errors.Join(ErrDurabilityUncertain, err)
	}

	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true

	return errors.Join(s.lock.Close(), s.parent.Close())
}
