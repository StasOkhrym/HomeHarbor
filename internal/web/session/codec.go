// Package session owns browser cookie, CSRF and confirmation proofs. Control
// identity storage remains the authority for whether an opaque session is live.
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	CookieName     = "__Host-homeharbor_admin"
	CSRFCookieName = "__Host-homeharbor_csrf"
	CSRFHeaderName = "X-CSRF-Token"
)

// ActionConfirmation binds a review form to one browser's CSRF cookie and
// exact action payload. It is separate from the companion signing root.
type ActionConfirmation interface {
	SignAction(string, []byte) string
	VerifyAction(string, []byte, string) bool
}

type Codec struct {
	key    []byte
	random func([]byte) (int, error)
}

func NewCodec(key []byte, random func([]byte) (int, error)) (*Codec, error) {
	if len(key) < 32 {
		return nil, errors.New("session signing key must be at least 32 bytes")
	}

	if random == nil {
		random = rand.Read
	}

	return &Codec{key: append([]byte(nil), key...), random: random}, nil
}

func (c *Codec) SessionCookie(token string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name: CookieName, Value: token + "." + c.sign("session."+token),
		Path: "/", Expires: expires, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (c *Codec) SessionToken(request *http.Request) (string, bool) {
	cookie, err := request.Cookie(CookieName)
	if err != nil {
		return "", false
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return "", false
	}

	expected := c.sign("session." + parts[0])
	// Constant-time comparison avoids leaking a useful signature prefix.
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return "", false
	}

	return parts[0], true
}

func (c *Codec) CSRFCookie(sessionToken string, expires time.Time) (*http.Cookie, error) {
	nonce := make([]byte, 24)
	n, err := c.random(nonce)
	if err != nil {
		return nil, fmt.Errorf("generate csrf nonce: %w", err)
	}
	if n != len(nonce) {
		return nil, fmt.Errorf("generate csrf nonce: %w", io.ErrUnexpectedEOF)
	}

	encoded := base64.RawURLEncoding.EncodeToString(nonce)

	return &http.Cookie{
		Name:  CSRFCookieName,
		Value: encoded + "." + c.sign("csrf."+sessionToken+"."+encoded),
		Path:  "/", Expires: expires, Secure: true, HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	}, nil
}

func (c *Codec) ValidCSRF(request *http.Request, sessionToken string) bool {
	cookie, err := request.Cookie(CSRFCookieName)
	header := request.Header.Get(CSRFHeaderName)
	if header == "" && strings.HasPrefix(
		request.Header.Get("Content-Type"), "application/x-www-form-urlencoded",
	) {
		// Ordinary browser forms cannot send a custom header. ParseForm caches
		// the body for the form handler; JSON API writes require the header.
		_ = request.ParseForm()
		header = request.PostForm.Get("_csrf")
	}

	if err != nil || header == "" ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
		return false
	}

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 {
		return false
	}

	expected := c.sign("csrf." + sessionToken + "." + parts[0])

	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func (c *Codec) SignAction(csrf string, payload []byte) string {
	return c.sign("browser-action.v1." + csrf + "." + string(payload))
}

func (c *Codec) VerifyAction(csrf string, payload []byte, proof string) bool {
	expected := c.SignAction(csrf, payload)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(proof)) == 1
}

func (c *Codec) sign(value string) string {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write([]byte(value))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
