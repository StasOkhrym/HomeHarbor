// Package companion contains the local trust-anchor primitives used by the
// Mac companion. The control plane receives only the public key and signed
// diffs; this package never sends the private key over HTTP.
package companion

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
)

const (
	maxRootKeyFileSize = 16 << 10
	unlockIdleTTL      = 15 * time.Minute
)

var ErrRootKeyLocked = errors.New("trusted companion root key is locked")

// RootKeyStore encrypts an Ed25519 root key with age's scrypt recipient. The
// file is replaced atomically so a failed write cannot leave a partially
// written trust anchor that looks valid to a later startup.
type RootKeyStore struct {
	path string
}

func NewRootKeyStore(path string) (*RootKeyStore, error) {
	if path == "" {
		return nil, errors.New("root key path is required")
	}

	return &RootKeyStore{path: path}, nil
}

// Create generates and persists a new root key. It refuses to overwrite an
// existing key because replacing it would invalidate every paired gateway.
func (s *RootKeyStore) Create(passphrase string) (ed25519.PublicKey, error) {
	if passphrase == "" {
		return nil, errors.New("root key passphrase is required")
	}

	if _, err := os.Stat(s.path); err == nil {
		return nil, errors.New("root key already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	if err := s.save(privateKey, passphrase); err != nil {
		return nil, err
	}

	return append(ed25519.PublicKey(nil), publicKey...), nil
}

// Save stores a caller-provided key for test/recovery tooling. Production
// setup should prefer Create so accidental key replacement is impossible.
func (s *RootKeyStore) Save(privateKey ed25519.PrivateKey, passphrase string) error {
	if len(privateKey) != ed25519.PrivateKeySize || passphrase == "" {
		return errors.New("private key and passphrase are required")
	}
	return s.save(privateKey, passphrase)
}

func (s *RootKeyStore) save(privateKey ed25519.PrivateKey, passphrase string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".root-key-*")
	if err != nil {
		return err
	}

	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		_ = temporary.Close()
		return err
	}

	encrypted, err := age.Encrypt(temporary, recipient)
	if err != nil {
		_ = temporary.Close()
		return err
	}

	if _, err := encrypted.Write(privateKey); err != nil {
		_ = encrypted.Close()
		_ = temporary.Close()

		return err
	}

	if err := encrypted.Close(); err != nil {
		_ = temporary.Close()
		return err
	}

	if err := temporary.Close(); err != nil {
		return err
	}

	return os.Rename(temporaryPath, s.path)
}

// Unlock decrypts the key into memory. Callers should keep the returned bytes
// only in a short-lived Session and call Close when the companion exits.
func (s *RootKeyStore) Unlock(passphrase string) (ed25519.PrivateKey, error) {
	if passphrase == "" {
		return nil, ErrRootKeyLocked
	}
	file, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	decrypted, err := age.Decrypt(io.LimitReader(file, maxRootKeyFileSize), mustIdentity(passphrase))
	if err != nil {
		_ = file.Close()
		return nil, ErrRootKeyLocked
	}
	privateKey, err := io.ReadAll(io.LimitReader(decrypted, ed25519.PrivateKeySize+1))
	_ = file.Close()
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrRootKeyLocked
	}
	return ed25519.PrivateKey(append([]byte(nil), privateKey...)), nil
}

func mustIdentity(passphrase string) age.Identity {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		// NewScryptIdentity only rejects an empty passphrase, which Unlock checks.
		panic(err)
	}

	return identity
}

// Session caches one unlocked root key and expires it after inactivity. The
// mutex protects both the key and timestamp because the companion may serve
// the browser and device approval handlers concurrently.
type Session struct {
	mu         sync.Mutex
	privateKey ed25519.PrivateKey
	lastUsed   time.Time
	now        func() time.Time
}

func NewSession(now func() time.Time) *Session {
	if now == nil {
		now = time.Now
	}

	return &Session{now: now}
}

func (s *Session) Unlock(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrRootKeyLocked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.privateKey = append(s.privateKey[:0], key...)
	s.lastUsed = s.now()

	return nil
}

func (s *Session) PrivateKey() (ed25519.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.privateKey) != ed25519.PrivateKeySize || s.now().Sub(s.lastUsed) >= unlockIdleTTL {
		s.clearLocked()
		return nil, ErrRootKeyLocked
	}

	s.lastUsed = s.now()

	return ed25519.PrivateKey(append([]byte(nil), s.privateKey...)), nil
}

func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearLocked()
}

func (s *Session) clearLocked() {
	for index := range s.privateKey {
		s.privateKey[index] = 0
	}

	s.privateKey = nil
	s.lastUsed = time.Time{}
}
