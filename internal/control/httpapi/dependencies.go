package httpapi

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Dependencies separates transport assembly from domain service capabilities.
// Missing optional resources remain unavailable; security authority is explicit.
type Dependencies struct {
	Resources       ResourceDependencies
	Browser         BrowserDependencies
	Security        SecurityDependencies
	Relay           RelayDependencies
	Observability   ObservabilityDependencies
	Activation      ActivationDependencies
	Coordination    http.Handler
	SnapshotHistory http.Handler
}

// ResourceDependencies contains consumer-owned application ports, not stores.
type ResourceDependencies struct {
	Devices             DeviceService
	Routes              RouteService
	Policy              PolicyService
	Services            ServiceCatalog
	Audit               AuditReader
	Invites             InviteService
	Snapshots           SnapshotService
	SnapshotBroadcaster SnapshotBroadcaster
}

// BrowserDependencies binds login rendering and mutation checks explicitly.
type BrowserDependencies struct {
	API                http.Handler
	LoginPage          http.Handler
	LoginAsset         http.Handler
	MutationAuthorizer func(context.Context, *http.Request) (bool, error)
	ActionConfirmation BrowserActionConfirmation
}

// SecurityDependencies does not select fallback authorities on store failure.
type SecurityDependencies struct {
	Authorizer        Authorizer
	TrustedProxyCIDRs []netip.Prefix
	RootPublicKey     ed25519.PublicKey
	APILimiter        *RateLimiter
	AuthLimiter       *RateLimiter
	DeviceLimiter     *RateLimiter
	Challenges        ChallengeRepository
	CompanionTTL      time.Duration
	StoreTimeout      time.Duration
}

// RelayDependencies keeps ticket issuance coupled to explicit peer authority.
type RelayDependencies struct {
	Issuer         RelaySessionIssuer
	PeerAuthorizer RelayPeerAuthorizer
	URL            string
	UDPAddress     string
	TTL            time.Duration
}

// ObservabilityDependencies receives readiness from the runtime's actual owners.
type ObservabilityDependencies struct {
	Logger  *slog.Logger
	Ready   func(context.Context) error
	Metrics http.Handler
}

// ActivationDependencies delegates possession checks to the activation workflow.
type ActivationDependencies struct {
	Challenge http.HandlerFunc
	Claim     http.HandlerFunc
}

// NewServer validates coupled capabilities before exposing an HTTP handler.
func NewServer(deps Dependencies) (*Server, error) {
	security := deps.Security
	if security.Authorizer == nil {
		return nil, errors.New("HTTP admin authorizer is required")
	}
	for _, limiter := range []*RateLimiter{security.APILimiter, security.AuthLimiter, security.DeviceLimiter} {
		if limiter == nil || limiter.limit <= 0 || limiter.window <= 0 ||
			(limiter.shared == nil && limiter.clients == nil) {
			return nil, errors.New("HTTP rate limits require explicit valid authority")
		}
	}
	browser := deps.Browser
	if browser.API != nil || browser.LoginPage != nil || browser.LoginAsset != nil {
		if browser.API == nil || browser.LoginPage == nil || browser.LoginAsset == nil ||
			browser.MutationAuthorizer == nil {
			return nil, errors.New(
				"browser handlers and mutation authorization must be configured together",
			)
		}
	}
	if (deps.Activation.Challenge == nil) != (deps.Activation.Claim == nil) {
		return nil, errors.New("activation challenge and claim must be configured together")
	}
	relay := deps.Relay
	if relay.Issuer != nil || relay.URL != "" || relay.UDPAddress != "" ||
		relay.PeerAuthorizer != nil {
		if relay.Issuer == nil || relay.PeerAuthorizer == nil || relay.URL == "" ||
			relay.TTL <= 0 ||
			deps.Resources.Devices == nil {
			return nil, errors.New(
				"relay issuance requires devices, peer authorization, URL and ticket lifetime",
			)
		}
	}
	if len(security.RootPublicKey) != 0 && (len(security.RootPublicKey) != ed25519.PublicKeySize ||
		security.Challenges == nil || security.CompanionTTL <= 0) {
		return nil, errors.New(
			"companion trust requires a public key, challenge authority and lifetime",
		)
	}
	logger := deps.Observability.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Limiter pointers are handed to this server; finish validating the entire
	// dependency graph before applying their configured store deadline.
	if security.StoreTimeout > 0 {
		security.AuthLimiter.storeTimeout = security.StoreTimeout
		security.DeviceLimiter.storeTimeout = security.StoreTimeout
	}

	server := &Server{
		devices:             deps.Resources.Devices,
		routes:              deps.Resources.Routes,
		policy:              deps.Resources.Policy,
		services:            deps.Resources.Services,
		audit:               deps.Resources.Audit,
		invites:             deps.Resources.Invites,
		snapshots:           deps.Resources.Snapshots,
		snapshotBroadcaster: deps.Resources.SnapshotBroadcaster,
		authorizer:          security.Authorizer,
		apiLimiter:          security.APILimiter,
		authLimiter:         security.AuthLimiter,
		deviceLimiter:       security.DeviceLimiter,
		trustedProxy:        append([]netip.Prefix(nil), security.TrustedProxyCIDRs...),
		companionRoot:       append(ed25519.PublicKey(nil), security.RootPublicKey...),
		browserAPI:          browser.API,
		loginPage:           browser.LoginPage,
		loginAsset:          browser.LoginAsset,
		mutationAuthorizer:  browser.MutationAuthorizer,
		actionConfirmation:  browser.ActionConfirmation,
		activationChallenge: deps.Activation.Challenge,
		activationClaim:     deps.Activation.Claim,
		relayIssuer:         relay.Issuer,
		relayPeerAuthorizer: relay.PeerAuthorizer,
		relayURL:            strings.TrimRight(relay.URL, "/"),
		relayUDPAddress:     strings.TrimSpace(relay.UDPAddress),
		relayTTL:            relay.TTL,
		coordination:        deps.Coordination,
		snapshotHistory:     deps.SnapshotHistory,
		logger:              logger,
		ready:               deps.Observability.Ready,
		metrics:             deps.Observability.Metrics,
	}
	if len(server.companionRoot) != 0 {
		server.companionChallenges = newCompanionChallengeStore(
			security.Challenges,
			security.CompanionTTL,
		)
	}
	return server, nil
}
