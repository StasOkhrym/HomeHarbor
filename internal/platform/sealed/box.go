// Package sealed provides account-bound, purpose-separated private payloads.
// It owns no storage, transport, authorization or credential lifecycle.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
)

var ErrInvalid = errors.New("invalid sealed payload")

const maxPayload = 1 << 20

type Box struct{ aead cipher.AEAD }

func New(master []byte, purpose string) (*Box, error) {
	if len(master) != 32 || len(purpose) < 1 || len(purpose) > 128 ||
		strings.ContainsRune(purpose, 0) {
		return nil, ErrInvalid
	}

	key, err := hkdf.Key(sha256.New, master, nil, "homeharbor.sealed."+purpose, 32)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}

	return &Box{aead: aead}, nil
}

func (b *Box) Seal(owner string, plaintext []byte) ([]byte, error) {
	if len(owner) < 1 || len(owner) > 128 || len(plaintext) > maxPayload {
		return nil, ErrInvalid
	}

	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	envelope := append([]byte{1}, nonce...)

	return b.aead.Seal(envelope, nonce, plaintext, append([]byte{1}, []byte(owner)...)), nil
}

func (b *Box) Open(owner string, envelope []byte) ([]byte, error) {
	if len(owner) < 1 || len(owner) > 128 ||
		len(envelope) < 1+b.aead.NonceSize()+b.aead.Overhead() ||
		len(envelope) > 1+b.aead.NonceSize()+b.aead.Overhead()+maxPayload ||
		envelope[0] != 1 {
		return nil, ErrInvalid
	}

	nonce := envelope[1 : 1+b.aead.NonceSize()]
	plaintext, err := b.aead.Open(
		nil,
		nonce,
		envelope[1+b.aead.NonceSize():],
		append([]byte{1}, []byte(owner)...),
	)
	if err != nil {
		return nil, ErrInvalid
	}

	return plaintext, nil
}
