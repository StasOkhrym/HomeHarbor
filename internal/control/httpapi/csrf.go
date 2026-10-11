package httpapi

import (
	"crypto/rand"
	"net/http"
	"time"

	websession "github.com/StasOkhrym/homeharbor/internal/web/session"
)

const (
	csrfCookieName = websession.CSRFCookieName
	csrfHeaderName = websession.CSRFHeaderName
)

// Overridden only by the entropy-failure characterization tests. The codec
// receives a closure so a test can change this after BrowserAuth construction.
var readRandom = rand.Read

func (a *BrowserAuth) csrfCookie(token string, expires time.Time) (*http.Cookie, error) {
	return a.codec.CSRFCookie(token, expires)
}

func (a *BrowserAuth) validCSRF(request *http.Request, token string) bool {
	return a.codec.ValidCSRF(request, token)
}
