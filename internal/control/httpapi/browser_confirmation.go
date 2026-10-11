package httpapi

import websession "github.com/StasOkhrym/homeharbor/internal/web/session"

// BrowserActionConfirmation is consumed by protected review-form handlers.
// Cookie/CSRF proof semantics are owned by the browser session module.
type BrowserActionConfirmation = websession.ActionConfirmation

func (a *BrowserAuth) SignAction(csrf string, payload []byte) string {
	return a.codec.SignAction(csrf, payload)
}

func (a *BrowserAuth) VerifyAction(csrf string, payload []byte, proof string) bool {
	return a.codec.VerifyAction(csrf, payload, proof)
}
