package companion

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRootKeyStoreRoundTripAndRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.age")
	store, err := NewRootKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, err := store.Create("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := store.Unlock("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}

	if !privateKey.Public().(ed25519.PublicKey).Equal(publicKey) {
		t.Fatal("unlocked private key does not match public key")
	}

	if _, err := store.Create("another passphrase"); err == nil {
		t.Fatal("Create overwrote an existing root key")
	}

	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("root key permissions = %v, %v", info, err)
	}

	if _, err := store.Unlock("wrong"); !errors.Is(err, ErrRootKeyLocked) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
}

func TestRootKeySessionExpiresAfterIdlePeriod(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	session := NewSession(func() time.Time { return now })

	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}

	now = now.Add(14 * time.Minute)

	if _, err := session.PrivateKey(); err != nil {
		t.Fatal(err)
	}

	now = now.Add(16 * time.Minute)

	if _, err := session.PrivateKey(); !errors.Is(err, ErrRootKeyLocked) {
		t.Fatalf("expired session error = %v", err)
	}
}

func TestInviteIssuerKeepsCodeOutOfLinkFragment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.age")
	store, err := NewRootKeyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := store.Create("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := store.Unlock("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	session := NewSession(func() time.Time { return now })
	if err := session.Unlock(privateKey); err != nil {
		t.Fatal(err)
	}
	issuer := NewInviteIssuer(session, "home", "https://control.example/invite", "root-1", func() time.Time { return now })
	link, code, _, err := issuer.Issue("family", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(parsed.Fragment, "permit=") || !strings.Contains(parsed.Fragment, "invite_key=") || strings.Contains(parsed.Fragment, code) {
		t.Fatalf("invite fragment leaks or misses material: %q", parsed.Fragment)
	}
	if len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("issuer root public key has wrong size")
	}
}
