package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
)

type ownerSettingsReader struct {
	err   error
	calls int
}

func (s *ownerSettingsReader) Administrators(
	context.Context,
	identity.Principal,
) ([]identity.AccountSummary, error) {
	s.calls++
	return []identity.AccountSummary{
		{
			ID:            identity.OwnerAccountID,
			Email:         "owner@example.test",
			Role:          identity.RoleOwner,
			Status:        identity.AccountActive,
			EmailVerified: true,
			CreatedAt:     time.Now(),
		},
		{
			ID:        "pending-helper",
			Email:     "helper@example.test",
			Role:      identity.RoleAdmin,
			Status:    identity.AccountInvited,
			CreatedAt: time.Now(),
		},
		{
			ID:        "old-helper",
			Email:     "old@example.test",
			Role:      identity.RoleAdmin,
			Status:    identity.AccountRevoked,
			CreatedAt: time.Now(),
		},
	}, s.err
}

func (s *ownerSettingsReader) SMTPStatus(
	context.Context,
	identity.Principal,
) (workflows.MailStatus, error) {
	s.calls++
	return workflows.MailStatus{
		Configured:        true,
		Recipient:         "owner@example.test",
		RecipientVerified: true,
		Test:              notifications.TestStatus{State: "sent", Attempts: 1},
	}, s.err
}

func settingsPageRequest(path string, role identity.Role) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	if role != "" {
		request = request.WithContext(
			identity.WithPrincipal(
				request.Context(),
				identity.Principal{
					AccountID:       identity.OwnerAccountID,
					Email:           "owner@example.test",
					Role:            role,
					Purpose:         identity.SessionAdmin,
					AuthVersion:     1,
					AuthenticatedAt: time.Now(),
					Method:          "totp",
				},
			),
		)
	}

	return request
}

func TestAdministratorPageRequiresOwnerAndShowsProtectedAccountStates(t *testing.T) {
	reader := &ownerSettingsReader{}

	handler := NewHandler(Dependencies{Administrators: reader, EmailEnabled: true}).Routes()
	for _, role := range []identity.Role{"", identity.RoleAdmin} {
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, settingsPageRequest("/administrators", role))

		if w.Code != http.StatusForbidden || reader.calls != 0 ||
			strings.Contains(w.Body.String(), "helper@example.test") {
			t.Fatal("administrator directory escaped owner guard", w.Code)
		}
	}

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, settingsPageRequest("/administrators", identity.RoleOwner))

	if w.Code != http.StatusOK {
		t.Fatal("owner directory unavailable", w.Code)
	}

	for _, label := range []string{"owner@example.test", "helper@example.test", "old@example.test", "Owner account", "Invitation pending", "Access revoked", "data-account-action=", "Invite administrator", "fieldset disabled"} {
		if !strings.Contains(w.Body.String(), label) {
			t.Fatal("missing account state/action", label)
		}
	}

	if strings.Contains(w.Body.String(), `value="`+identity.OwnerAccountID+`"`) {
		t.Fatal("owner received revocation control")
	}

	reader.err = errors.New("PRIVATE_SQL_DETAIL")
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, settingsPageRequest("/administrators", identity.RoleOwner))

	if w.Code != http.StatusServiceUnavailable ||
		strings.Contains(w.Body.String(), "PRIVATE_SQL") ||
		strings.Contains(w.Body.String(), "data-account-action=") {
		t.Fatal("directory outage remained writable", w.Code)
	}
}

func TestMailSettingsPageReportsDurableStatusWithoutClaimingHealth(t *testing.T) {
	reader := &ownerSettingsReader{}

	handler := NewHandler(Dependencies{MailSettings: reader}).Routes()
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, settingsPageRequest("/mail", identity.RoleAdmin))

	if w.Code != http.StatusForbidden || reader.calls != 0 {
		t.Fatal("admin read mail settings", w.Code)
	}

	w = httptest.NewRecorder()

	handler.ServeHTTP(w, settingsPageRequest("/mail", identity.RoleOwner))

	if w.Code != http.StatusOK {
		t.Fatal("owner mail settings unavailable", w.Code)
	}

	for _, label := range []string{"owner@example.test", "Configured", "Accepted by SMTP server", "Send test email", "fieldset disabled"} {
		if !strings.Contains(w.Body.String(), label) {
			t.Fatal("missing durable mail presentation", label)
		}
	}

	for _, forbidden := range []string{`name="to"`, `name="recipient"`, "SMTP is healthy", "Delivered to inbox"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("unsafe SMTP implication/input", forbidden)
		}
	}

	reader.err = errors.New("PRIVATE_SMTP_DETAIL")
	w = httptest.NewRecorder()

	handler.ServeHTTP(w, settingsPageRequest("/mail", identity.RoleOwner))

	if w.Code != http.StatusServiceUnavailable ||
		strings.Contains(w.Body.String(), "PRIVATE_SMTP") ||
		strings.Contains(w.Body.String(), "data-account-action=") {
		t.Fatal("mail outage remained writable", w.Code)
	}
}
