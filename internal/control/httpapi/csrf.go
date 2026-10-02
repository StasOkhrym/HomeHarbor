package httpapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	csrfCookieName = "__Host-homeharbor_csrf"
	csrfHeaderName = "X-CSRF-Token"
)

var readRandom = rand.Read

func (a *BrowserAuth) csrfCookie(sessionToken string, expires time.Time) (*http.Cookie, error) {
	nonce := make([]byte, 24)
	if _, err := readRandom(nonce); err != nil {
		return nil, fmt.Errorf("generate csrf nonce: %w", err)
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	value := encodedNonce + "." + a.sign("csrf."+sessionToken+"."+encodedNonce)
	// JavaScript must echo this cookie in a header, so HttpOnly is intentionally
	// false. SameSite and the session-bound MAC prevent reuse from another site
	// or another authenticated browser session.
	return &http.Cookie{
		Name:     csrfCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteStrictMode,
	}, nil
}

func (a *BrowserAuth) validCSRF(request *http.Request, sessionToken string) bool {
	cookie, err := request.Cookie(csrfCookieName)
	header := request.Header.Get(csrfHeaderName)
	if header == "" &&
		strings.HasPrefix(request.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		// Browser forms cannot set a custom header. ParseForm caches the body so
		// the subsequent form handler sees the same values, while JSON API
		// requests continue to require the explicit CSRF header.
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
	expected := a.sign("csrf." + sessionToken + "." + parts[0])
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func (a *BrowserAuth) sign(value string) string {
	mac := hmac.New(sha256.New, a.signingKey)
	_, _ = mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
