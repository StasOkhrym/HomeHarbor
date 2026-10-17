package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
)

func TestRequestAuditFactsUseTrustedIPAndCoarseClient(t *testing.T) {
	for _, tc := range []struct{ name, peer, forwarded, want string }{
		{"untrusted", "192.0.2.4:123", "203.0.113.8", "192.0.2.4"},
		{"trusted chain", "10.0.0.2:123", "203.0.113.9, 192.0.2.8, 10.0.0.3", "192.0.2.8"},
		{"invalid remote", "SECRET_REMOTE", "203.0.113.8", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{trustedProxy: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
			var got audit.Context

			h := requestIDMiddleware(
				s.auditContextMiddleware(
					http.HandlerFunc(
						func(_ http.ResponseWriter, r *http.Request) { got = audit.FromContext(r.Context()) },
					),
				),
			)
			r := httptest.NewRequest("GET", "/admin/activity", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			r.Header.Set("X-Request-ID", "request-1")
			r.Header.Set(
				"User-Agent",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15 SECRET_UA",
			)
			h.ServeHTTP(httptest.NewRecorder(), r)

			if got.SourceIP != tc.want || got.Browser != "Safari" || got.Platform != "macos" ||
				got.CorrelationID != "request-1" ||
				got.ActorType != "unknown" {
				t.Fatalf("unsafe/missing request facts: %+v", got)
			}
		})
	}
}

func TestAdminBoundaryAddsVerifiedPrincipalActor(t *testing.T) {
	s := &Server{authorizer: allowAuthorizer{}}
	var got audit.Context

	h := s.requireAdmin(
		http.HandlerFunc(
			func(_ http.ResponseWriter, r *http.Request) { got = audit.FromContext(r.Context()) },
		),
	)

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/admin/activity", nil))

	if got.ActorType != "admin" || got.ActorID != "admin" {
		t.Fatalf("authenticated actor missing: %+v", got)
	}
}

type personalAuthorizer struct{}

func (personalAuthorizer) AdminPrincipal(
	context.Context,
	*http.Request,
) (identity.Principal, error) {
	return identity.Principal{
		AccountID:   "account-a",
		Email:       "a@example.test",
		Role:        identity.RoleAdmin,
		Purpose:     identity.SessionAdmin,
		Method:      "totp",
		AuthVersion: 3,
	}, nil
}

func TestAdminBoundaryUsesVerifiedPersonalAuditIdentity(t *testing.T) {
	server := &Server{authorizer: personalAuthorizer{}}
	var facts audit.Context

	server.requireAdmin(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { facts = audit.FromContext(r.Context()) })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/activity", nil))

	if facts.ActorID != "account-a" || facts.ActorName != "a@example.test" ||
		facts.Authentication != "password_totp" {
		t.Fatalf("personal authority collapsed into global administrator: %+v", facts)
	}
}
