package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var authorized bool
		var principal identity.Principal
		var err error
		if s.authorizer != nil {
			principal, err = s.authorizer.AdminPrincipal(r.Context(), r)
			authorized = err == nil && principal.CanManageNetwork()
		}

		if authorized && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Method != http.MethodOptions {
			authorized = false
			if s.mutationAuthorizer != nil {
				authorized, err = s.mutationAuthorizer(r.Context(), r)
			}
		}

		if errors.Is(err, identity.ErrInvalidCredential) {
			err = nil
			authorized = false
		}

		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "authentication state unavailable")
			return
		}
		if !authorized {
			// Only normal browser reads redirect. API clients retain typed 401
			// responses, and expired POSTs are never replayed after a new login.
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin") &&
				!strings.HasPrefix(r.URL.Path, "/api/") {
				if r.Header.Get("HX-Request") == "true" {
					w.Header().Set("HX-Redirect", "/admin/login")
				} else {
					http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
					return
				}
			}

			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		facts := audit.FromContext(r.Context())
		facts.ActorType, facts.ActorID, facts.ActorName = "admin", principal.AccountID, principal.Email
		facts.Authentication = "password_" + principal.Method
		next.ServeHTTP(
			w,
			r.WithContext(identity.WithPrincipal(audit.WithContext(r.Context(), facts), principal)),
		)
	})
}

// requireDevice authenticates the short-lived bearer credential used by Linux
// and native clients. It never accepts the browser session cookie, keeping
// admin privileges and end-user device access on separate auth paths.
func (s *Server) requireDevice(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		credential := strings.TrimSpace(
			strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "),
		)
		device, err := s.devices.Authenticate(r.Context(), credential)
		if err != nil || device.Status != devices.StatusActive {
			writeError(w, http.StatusUnauthorized, "device authentication required")
			return
		}

		facts := audit.FromContext(r.Context())
		facts.ActorType, facts.ActorID, facts.ActorName = "device", device.ID, device.Name
		facts.Authentication = "device_credential"
		ctx := context.WithValue(audit.WithContext(r.Context(), facts), deviceContextKey{}, device)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type deviceContextKey struct{}

func deviceFromContext(ctx context.Context) (devices.Device, bool) {
	device, ok := ctx.Value(deviceContextKey{}).(devices.Device)
	return device, ok
}
