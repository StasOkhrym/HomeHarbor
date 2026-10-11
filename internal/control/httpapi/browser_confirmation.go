package httpapi

import websession "github.com/StasOkhrym/homeharbor/internal/web/session"

// BrowserActionConfirmation is consumed by protected review-form handlers.
// Cookie/CSRF proof semantics are owned by the browser session module.
type BrowserActionConfirmation = websession.ActionConfirmation
