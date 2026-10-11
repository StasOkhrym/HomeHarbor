package admin

import (
	"bytes"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/web/assets"
)

var enrollmentTokenPage = assets.HTML("enrollment-token.html")

var enrollmentTokenTemplate = template.Must(
	template.New("enrollment-token").Parse(string(enrollmentTokenPage)),
)

func (s *Handler) issueEnrollmentTokenForm(w http.ResponseWriter, r *http.Request) {
	role := devices.Role(strings.TrimSpace(r.FormValue("role")))

	ttl, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("ttl_seconds")), 10, 64)
	if err != nil || ttl < 60 || ttl > 86400 {
		s.adminFormError(
			w,
			r,
			"invites",
			http.StatusUnprocessableEntity,
			"ttl_seconds",
			"Choose a lifetime between 1 minute and 24 hours.",
		)
		return
	}
	if role != devices.RoleClient && role != devices.RoleGateway {
		s.adminFormError(
			w,
			r,
			"invites",
			http.StatusUnprocessableEntity,
			"role",
			"Choose Client or Home gateway.",
		)
		return
	}
	if s.devices == nil {
		s.adminFormError(
			w,
			r,
			"invites",
			http.StatusServiceUnavailable,
			"form",
			"Device enrollment is unavailable.",
		)
		return
	}

	token, err := s.devices.IssueEnrollmentToken(r.Context(), role, time.Duration(ttl)*time.Second)
	if err != nil {
		s.adminFormError(
			w,
			r,
			"invites",
			http.StatusServiceUnavailable,
			"form",
			"A token could not be created. Try again shortly.",
		)
		return
	}

	// Plaintext is rendered exactly once, never put into a redirect, shared
	// dashboard model or log. Only a hash is retained by the devices repository.
	var output bytes.Buffer

	if err := enrollmentTokenTemplate.Execute(&output, token); err != nil {
		s.logger.Error("render enrollment token", "error", err)
		http.Error(
			w,
			"The token page could not be displayed. Create a new token.",
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(output.Bytes())
}
