package auth

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var mailTemplate = template.Must(
	template.New("mail-auth").Parse(string(assets.HTML("mail-auth.html"))),
)

type mailPageModel struct {
	Flow         string
	Title        string
	EmailEnabled bool
	Enrolling    bool
	Email        string
	Unavailable  bool
}

func mailFlow(path string) (string, string) {
	switch path {
	case "/admin/invitation":
		return "invitation", "Set up your admin account"
	case "/admin/reset-password":
		return "reset", "Reset your password"
	case "/admin/verify-email":
		return "verify", "Confirm your email"
	case "/admin/complete-account":
		return "enrollment", "Finish your account setup"
	default:
		return "", ""
	}
}

func (a *BrowserAuth) mailPage(w http.ResponseWriter, r *http.Request) {
	flow, title := mailFlow(r.URL.Path)
	model := mailPageModel{Flow: flow, Title: title, EmailEnabled: a.emailEnabled}
	status := http.StatusOK
	if a.mail == nil || a.enrollment == nil {
		model.Unavailable = true
		status = http.StatusServiceUnavailable
	}

	if flow == "enrollment" && !model.Unavailable {
		if cookie, err := r.Cookie(enrollmentCookieName); err == nil {
			subject, err := a.enrollmentSubject(r.Context(), cookie.Value)
			switch {
			case err == nil:
				model.Enrolling = true
				model.Email = subject.Email
				model.Title = "Protect your account"
			case errors.Is(err, identity.ErrInvalidCredential):
				http.SetCookie(w, expiredEnrollmentCookie())
			default:
				model.Unavailable = true
				status = http.StatusServiceUnavailable
			}
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	if err := mailTemplate.Execute(w, model); err != nil {
		a.logger.ErrorContext(r.Context(), "render account flow unavailable")
	}
}
