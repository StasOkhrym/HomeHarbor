package httpapi

import "crypto/subtle"

// BrowserActionConfirmation binds review forms to an authenticated session's
// CSRF token and exact action payload. It is not the companion signing root.
type BrowserActionConfirmation interface {
	SignAction(string, []byte) string
	VerifyAction(string, []byte, string) bool
}

// SignAction authenticates a browser confirmation using the existing cookie
// signing key, with a separate domain from session/CSRF signatures.
func (a *BrowserAuth) SignAction(csrf string, payload []byte) string {
	return a.sign("browser-action.v1." + csrf + "." + string(payload))
}

// VerifyAction rejects a confirmation copied to another session or payload.
func (a *BrowserAuth) VerifyAction(csrf string, payload []byte, proof string) bool {
	expected := a.SignAction(csrf, payload)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(proof)) == 1
}
