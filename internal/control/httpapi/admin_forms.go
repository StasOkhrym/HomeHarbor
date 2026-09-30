package httpapi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/network"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
)

//go:embed templates/enrollment-token.html
var enrollmentTokenPage []byte

var enrollmentTokenTemplate = template.Must(template.New("enrollment-token").Parse(string(enrollmentTokenPage)))

func csrfFormToken(request *http.Request) string {
	cookie, err := request.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) issueEnrollmentTokenForm(w http.ResponseWriter, r *http.Request) {
	role := devices.Role(strings.TrimSpace(r.FormValue("role")))
	ttlSeconds, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("ttl_seconds")), 10, 64)
	if err != nil || ttlSeconds <= 0 {
		http.Error(w, "TTL must be a positive number of seconds", http.StatusBadRequest)
		return
	}
	token, err := s.devices.IssueEnrollmentToken(r.Context(), role, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		http.Error(w, "could not create enrollment invite", http.StatusBadRequest)
		return
	}
	// The token is rendered once and never placed in a redirect query string,
	// access log field, or long-lived dashboard model. Operators can copy it
	// into the separate invite channel and then close this page.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := enrollmentTokenTemplate.Execute(w, map[string]any{
		"Token":     token.Token,
		"Role":      token.Role,
		"ExpiresAt": token.ExpiresAt,
	}); err != nil {
		s.logger.Error("render enrollment token", "error", err)
	}
}

func (s *Server) revokeDeviceForm(w http.ResponseWriter, r *http.Request) {
	if err := s.devices.Revoke(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, "could not revoke device", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "device-revoked")
}

func (s *Server) approveRouteForm(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Approve(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, "could not approve route", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "route-approved")
}

func (s *Server) rejectRouteForm(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Reject(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, "could not reject route", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "route-rejected")
}

func (s *Server) createRouteForm(w http.ResponseWriter, r *http.Request) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(r.FormValue("prefix")))
	if err != nil {
		http.Error(w, "route prefix must be a valid non-default CIDR", http.StatusBadRequest)
		return
	}
	resolver, err := netip.ParseAddr(strings.TrimSpace(r.FormValue("resolver")))
	if err != nil {
		http.Error(w, "DNS resolver must be a valid IP address", http.StatusBadRequest)
		return
	}
	item := controlnetwork.AdvertisementRequest{
		ID:              strings.TrimSpace(r.FormValue("id")),
		GatewayDeviceID: strings.TrimSpace(r.FormValue("gateway_device_id")),
		Prefix:          prefix,
		Resolver:        resolver,
		DomainSuffix:    strings.TrimSpace(r.FormValue("domain_suffix")),
	}
	if _, err := s.network.Advertise(r.Context(), item); err != nil {
		if errors.Is(err, controlnetwork.ErrInvalidAdvertisement) {
			http.Error(w, "route values are invalid", http.StatusBadRequest)
			return
		}
		http.Error(w, "could not create route advertisement", http.StatusInternalServerError)
		return
	}
	redirectAdmin(w, r, "route-created")
}

func (s *Server) createServiceForm(w http.ResponseWriter, r *http.Request) {
	item := controlservices.Service{
		ID:          strings.TrimSpace(r.FormValue("id")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		Kind:        controlservices.Kind(strings.TrimSpace(r.FormValue("kind"))),
		URL:         strings.TrimSpace(r.FormValue("url")),
		NativeURL:   strings.TrimSpace(r.FormValue("native_url")),
		HealthURL:   strings.TrimSpace(r.FormValue("health_url")),
		Description: strings.TrimSpace(r.FormValue("description")),
	}
	if _, err := s.services.Create(r.Context(), item); err != nil {
		if errors.Is(err, controlservices.ErrDuplicateID) {
			http.Error(w, "a service with this ID already exists", http.StatusConflict)
			return
		}
		http.Error(w, "service values are invalid", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "service-created")
}

func (s *Server) createProfileForm(w http.ResponseWriter, r *http.Request) {
	profile := controlservices.AccessProfile{
		ID:         strings.TrimSpace(r.FormValue("id")),
		Name:       strings.TrimSpace(r.FormValue("name")),
		DeviceIDs:  splitFormList(r.FormValue("device_ids")),
		ServiceIDs: splitFormList(r.FormValue("service_ids")),
	}
	if _, err := s.services.CreateProfile(r.Context(), profile); err != nil {
		if errors.Is(err, controlservices.ErrDuplicateID) {
			http.Error(w, "an access profile with this ID already exists", http.StatusConflict)
			return
		}
		http.Error(w, "access profile values are invalid", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "profile-created")
}

func (s *Server) replacePolicyForm(w http.ResponseWriter, r *http.Request) {
	var rules []policy.Rule
	if err := json.Unmarshal([]byte(r.FormValue("rules")), &rules); err != nil {
		http.Error(w, "policy must be a JSON array of rules", http.StatusBadRequest)
		return
	}
	if _, err := s.policy.Replace(r.Context(), rules); err != nil {
		http.Error(w, "policy contains invalid rules", http.StatusBadRequest)
		return
	}
	redirectAdmin(w, r, "policy-updated")
}

func splitFormList(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			items = append(items, value)
		}
	}
	return items
}

func redirectAdmin(w http.ResponseWriter, request *http.Request, notice string) {
	// Notices are fixed server-generated labels, never user input or token data.
	http.Redirect(w, request, "/admin/?notice="+url.QueryEscape(notice), http.StatusSeeOther)
}
