package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const passwordPHCPrefix = "$argon2id$v=19$m=65536,t=3,p=1$"

// PasswordHasher limits expensive work, including the dummy verification for
// unknown accounts. One instance is shared by the composition root. Parameters
// are deliberately fixed: persisted strings cannot request unbounded work.
type PasswordHasher struct{ slots chan struct{} }

func NewPasswordHasher(workers int) (*PasswordHasher, error) {
	if workers < 1 || workers > 4 {
		return nil, errors.New("password workers must be between 1 and 4")
	}

	return &PasswordHasher{slots: make(chan struct{}, workers)}, nil
}

func ValidateNewPassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 ||
		len(password) > 1024 {
		return errors.New("use 12 or more characters, at most 1024 bytes")
	}

	return nil
}

func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := ValidateNewPassword(password); err != nil {
		return "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash, err := h.derive(ctx, password, salt)
	if err != nil {
		return "", err
	}

	return passwordPHCPrefix + base64.RawStdEncoding.EncodeToString(
		salt,
	) + "$" + base64.RawStdEncoding.EncodeToString(
		hash,
	), nil
}

func (h *PasswordHasher) Verify(ctx context.Context, encoded, password string) error {
	if len(password) > 1024 {
		return ErrInvalidCredential
	}

	salt, want, valid := parsePasswordHash(encoded)
	if !valid {
		// Keep missing/malformed accounts on the same bounded KDF path. This is a
		// comparison sink only; it is never an account password or accepted proof.
		salt = make([]byte, 16)
		want = make([]byte, 32)
	}

	got, err := h.derive(ctx, password, salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 || !valid {
		return ErrInvalidCredential
	}

	return nil
}

func parsePasswordHash(encoded string) (salt, hash []byte, valid bool) {
	if len(encoded) > 512 || !strings.HasPrefix(encoded, passwordPHCPrefix) {
		return nil, nil, false
	}

	parts := strings.Split(strings.TrimPrefix(encoded, passwordPHCPrefix), "$")
	if len(parts) != 2 {
		return nil, nil, false
	}

	var err error

	salt, err = base64.RawStdEncoding.Strict().DecodeString(parts[0])
	if err != nil || len(salt) != 16 {
		return nil, nil, false
	}

	hash, err = base64.RawStdEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(hash) != 32 {
		return nil, nil, false
	}

	return salt, hash, true
}

func (h *PasswordHasher) derive(ctx context.Context, password string, salt []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	select {
	case h.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-h.slots }()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return hash, nil
}
