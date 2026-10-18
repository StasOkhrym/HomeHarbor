package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/platform/httpresponse"
)

type MailActions interface {
	RequestPasswordReset(context.Context, string) error
	RequestEmailVerification(context.Context, identity.Principal) error
	ResetPassword(context.Context, string, string) (identity.AccountSubject, error)
	AcceptInvitation(context.Context, string, string) (identity.AccountSubject, error)
	VerifyEmail(context.Context, string) (identity.AccountSubject, error)
	InviteAdmin(context.Context, identity.Principal, string) (identity.AccountSubject, error)
	RevokeAdmin(context.Context, identity.Principal, string) (identity.AccountSubject, error)
}

func (a *BrowserAuth) registerMailRoutes(router chi.Router) {
	router.Post("/password/reset/request", a.requestPasswordReset)
	router.Post("/password/reset/finish", a.resetPassword)
	router.Post("/email/verify", a.verifyEmail)
	router.Post("/invitation/accept", a.acceptInvitation)
}

func (a *BrowserAuth) requireMail(w http.ResponseWriter) bool {
	if a.mail != nil {
		return true
	}

	a.writeMailError(w, identity.ErrSecurityStateUnavailable)
	return false
}

func (a *BrowserAuth) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !a.requireMail(w) {
		return
	}

	var input struct {
		Email string `json:"email"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	err := a.mail.RequestPasswordReset(r.Context(), input.Email)
	a.auditAccount(r.Context(), "admin.password_reset_requested", identity.AccountSubject{}, err)
	if err != nil {
		a.writeMailError(w, err)
		return
	}

	httpresponse.WriteJSON(w, http.StatusAccepted, map[string]string{"next": "check_inbox"})
}

type mailPasswordInput struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func decodeMailPassword(w http.ResponseWriter, r *http.Request) (mailPasswordInput, bool) {
	var input mailPasswordInput
	if !httpresponse.DecodeJSON(w, r, &input) {
		return input, false
	}

	if err := identity.ValidateNewPassword(input.Password); err != nil {
		httpresponse.WriteError(
			w,
			http.StatusBadRequest,
			"use at least 12 characters, at most 1024 bytes",
		)
		return input, false
	}

	return input, true
}

func (a *BrowserAuth) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !a.requireMail(w) {
		return
	}

	input, ok := decodeMailPassword(w, r)
	if !ok {
		return
	}

	subject, err := a.mail.ResetPassword(r.Context(), input.Token, input.Password)
	a.auditAccount(mailProofAuditContext(r.Context()), "admin.password_reset", subject, err)
	if err != nil {
		a.writeMailError(w, err)
		return
	}

	http.SetCookie(w, expiredCookie(sessionCookieName))
	http.SetCookie(w, expiredCookie(csrfCookieName))
	http.SetCookie(w, expiredPreauthCookie())
	http.SetCookie(w, expiredEnrollmentCookie())
	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if !a.requireMail(w) {
		return
	}

	var input struct {
		Token string `json:"token"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	subject, err := a.mail.VerifyEmail(r.Context(), input.Token)
	a.auditAccount(mailProofAuditContext(r.Context()), "admin.email_verified", subject, err)
	if err != nil {
		a.writeMailError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (a *BrowserAuth) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !a.requireMail(w) || !a.requireEnrollment(w) {
		return
	}

	var input struct {
		mailPasswordInput
		Email string `json:"email"`
	}
	if !httpresponse.DecodeJSON(w, r, &input) {
		return
	}

	email, err := identity.CanonicalEmail(input.Email)
	if err != nil {
		httpresponse.WriteError(w, http.StatusBadRequest, "use the email from your invitation")
		return
	}

	if err := identity.ValidateNewPassword(input.Password); err != nil {
		httpresponse.WriteError(
			w,
			http.StatusBadRequest,
			"use at least 12 characters, at most 1024 bytes",
		)
		return
	}

	subject, err := a.mail.AcceptInvitation(r.Context(), input.Token, input.Password)
	a.auditAccount(mailProofAuditContext(r.Context()), "admin.invitation_accepted", subject, err)
	if err != nil {
		a.writeMailError(w, err)
		return
	}

	// The just-set password is verified against the committed invited account.
	// This produces setup proof only; failure remains resumable at its password page.
	http.SetCookie(w, expiredEnrollmentCookie())
	if email != subject.Email {
		httpresponse.WriteJSON(
			w,
			http.StatusAccepted,
			map[string]string{"next": "enrollment_password"},
		)
		return
	}

	issued, err := a.enrollment.Password(r.Context(), subject.Email, input.Password)
	if err != nil {
		httpresponse.WriteJSON(
			w,
			http.StatusAccepted,
			map[string]string{"next": "enrollment_password"},
		)
		return
	}

	http.SetCookie(w, passwordProofCookie(enrollmentCookieName, issued))
	httpresponse.WriteJSON(w, http.StatusOK, map[string]string{"next": "enrollment"})
}

func (a *BrowserAuth) writeMailError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrInvalidCredential):
		httpresponse.WriteError(w, http.StatusUnauthorized, "invalid or expired account proof")
	case errors.Is(err, identity.ErrRecentAuthentication):
		httpresponse.WriteError(
			w,
			http.StatusForbidden,
			"sign in again before changing account settings",
		)
	case errors.Is(err, identity.ErrMailRateLimited):
		httpresponse.WriteError(
			w,
			http.StatusTooManyRequests,
			"wait a minute before requesting another email",
		)
	default:
		httpresponse.WriteError(w, http.StatusServiceUnavailable, "account email is unavailable")
	}
}

func (a *BrowserAuth) registerAccountMailRoutes(router chi.Router) {
	router.Post("/email/verification", func(w http.ResponseWriter, r *http.Request) {
		if !a.requireMail(w) {
			return
		}
		principal, _ := identity.PrincipalFromContext(r.Context())
		ctx := principalAuditContext(r.Context(), principal)
		err := a.mail.RequestEmailVerification(ctx, principal)
		a.auditAccount(
			ctx,
			"admin.verification_requested",
			identity.AccountSubject{ID: principal.AccountID, Email: principal.Email},
			err,
		)
		if err != nil {
			a.writeMailError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	router.Group(func(owner chi.Router) {
		owner.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				principal, ok := identity.PrincipalFromContext(r.Context())
				if !ok || !principal.CanManageAccounts() {
					httpresponse.WriteError(
						w,
						http.StatusForbidden,
						"only the owner can manage administrators",
					)
					return
				}
				if !a.requireMail(w) {
					return
				}
				next.ServeHTTP(w, r)
			})
		})
		owner.Post("/admins/invite", func(w http.ResponseWriter, r *http.Request) {
			var input struct {
				Email string `json:"email"`
			}
			if !httpresponse.DecodeJSON(w, r, &input) {
				return
			}
			principal, _ := identity.PrincipalFromContext(r.Context())
			ctx := principalAuditContext(r.Context(), principal)
			subject, err := a.mail.InviteAdmin(ctx, principal, input.Email)
			a.auditAccount(ctx, "admin.invited", subject, err)
			if err != nil {
				a.writeMailError(w, err)
				return
			}
			w.WriteHeader(http.StatusCreated)
		})
		owner.Post("/admins/{accountID}/revoke", func(w http.ResponseWriter, r *http.Request) {
			principal, _ := identity.PrincipalFromContext(r.Context())
			ctx := principalAuditContext(r.Context(), principal)
			subject, err := a.mail.RevokeAdmin(ctx, principal, chi.URLParam(r, "accountID"))
			a.auditAccount(ctx, "admin.revoked", subject, err)
			if err != nil {
				a.writeMailError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
	})
}

type AccountAuthAuditor interface {
	RecordAccount(context.Context, string, identity.AccountSubject, bool) error
}

func mailProofAuditContext(ctx context.Context) context.Context {
	facts := audit.FromContext(ctx)
	facts.Authentication = "identity_proof"
	// An existing unrelated admin cookie does not identify the mailbox-proof actor.
	facts.ActorType = "unknown"
	facts.ActorID = ""
	facts.ActorName = ""

	return audit.WithContext(ctx, facts)
}

func (a *BrowserAuth) auditAccount(
	ctx context.Context,
	action string,
	subject identity.AccountSubject,
	err error,
) {
	if a.auditor == nil {
		return
	}
	recorder, ok := a.auditor.(AccountAuthAuditor)
	if !ok {
		a.logger.WarnContext(ctx, "account audit capability unavailable")
		return
	}
	facts := audit.FromContext(ctx)
	switch {
	case errors.Is(err, identity.ErrInvalidCredential):
		facts.Reason = "invalid_proof"
	case errors.Is(err, identity.ErrMailRateLimited):
		facts.Reason = "rate_limited"
	}
	if err := recorder.RecordAccount(
		audit.WithContext(ctx, facts),
		action,
		subject,
		err == nil,
	); err != nil {
		a.logger.ErrorContext(ctx, "account audit unavailable")
	}
}
