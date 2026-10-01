package httpapi

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
)

// DeviceService is intentionally defined by the HTTP consumer. Keeping this
// interface narrow lets the devices module evolve without exposing repository
// details or forcing unrelated transports to depend on HTTP-specific behavior.
type DeviceService interface {
	IssueEnrollmentToken(context.Context, devices.Role, time.Duration) (devices.IssuedToken, error)
	Enroll(context.Context, devices.EnrollRequest) (devices.Device, error)
	List(context.Context) ([]devices.Device, error)
	Revoke(context.Context, string) error
	Authenticate(context.Context, string) (devices.Device, error)
	Device(context.Context, string) (devices.Device, error)
	RotateCredential(context.Context, string, string) (string, error)
}

type Authorizer interface {
	IsAdmin(context.Context, *http.Request) (bool, error)
}

// Server composes optional module capabilities at the HTTP boundary. Domain
// services remain unaware of chi and continue to satisfy narrow interfaces.
type Server struct {
	devices             DeviceService
	routes              RouteService
	policy              PolicyService
	authorizer          Authorizer
	mutationAuthorizer  func(context.Context, *http.Request) (bool, error)
	browserAPI          http.Handler
	loginPage           http.Handler
	loginAsset          http.Handler
	logger              *slog.Logger
	coordination        http.Handler
	snapshotHistory     http.Handler
	metrics             http.Handler
	ready               func(context.Context) error
	apiLimiter          *RateLimiter
	authLimiter         *RateLimiter
	deviceLimiter       *RateLimiter
	services            ServiceCatalog
	audit               AuditReader
	invites             InviteService
	activationChallenge http.HandlerFunc
	activationClaim     http.HandlerFunc
	snapshots           SnapshotService
	snapshotBroadcaster SnapshotBroadcaster
	companionRoot       ed25519.PublicKey
	companionChallenges *companionChallengeStore
	relayIssuer         RelaySessionIssuer
	relayURL            string
	relayUDPAddress     string
	relayTTL            time.Duration
	relayPeerAuthorizer RelayPeerAuthorizer
	trustedProxy        []netip.Prefix
	actionConfirmation  BrowserActionConfirmation
}

type RouteService interface {
	Advertise(context.Context, controlroutes.AdvertisementRequest) (controlroutes.Advertisement, error)
	Approve(context.Context, string) error
	Reject(context.Context, string) error
	List(context.Context) ([]controlroutes.Advertisement, error)
}
type ServerOption func(*Server)

// WithSnapshotHistoryHandler binds the device-authenticated catch-up transport.
// Its dependency is explicit rather than discovered on a WebSocket handler.
func WithSnapshotHistoryHandler(handler http.Handler) ServerOption {
	return func(s *Server) { s.snapshotHistory = handler }
}

// WithActivationHandlers explicitly binds device possession endpoints. Neither
// handler is admin-authenticated: the workflow verifies its one-use key proof.
func WithActivationHandlers(challenge, claim http.HandlerFunc) ServerOption {
	return func(s *Server) { s.activationChallenge = challenge; s.activationClaim = claim }
}

// WithBrowserHandlers makes transport capabilities explicit at composition;
// the authorization interface cannot silently acquire HTTP routes at runtime.
func WithBrowserHandlers(
	api, login, asset http.Handler,
	mutation func(context.Context, *http.Request) (bool, error),
) ServerOption {
	return func(s *Server) {
		s.browserAPI = api
		s.loginPage = login
		s.loginAsset = asset
		s.mutationAuthorizer = mutation
	}
}

func WithMutationAuthorizer(authorize func(context.Context, *http.Request) (bool, error)) ServerOption {
	return func(s *Server) { s.mutationAuthorizer = authorize }
}

// WithSharedRateLimits scopes distributed guessing quotas to operations that
// introduce trust. Credential rotation and established coordination remain
// independent of Redis availability.
func WithSharedRateLimits(store RateLimitStore) ServerOption {
	return func(s *Server) {
		s.authLimiter = NewSharedRateLimiter(store, "auth", 5, time.Minute)
		s.deviceLimiter = NewSharedRateLimiter(store, "onboarding", 10, time.Minute)
	}
}

func WithSharedChallenges(repository ChallengeRepository) ServerOption {
	return func(s *Server) {
		if s.companionChallenges == nil {
			s.companionChallenges = newCompanionChallengeStore()
		}
		s.companionChallenges.shared = repository
	}
}

// AuditReader is deliberately read-only at the HTTP boundary. Audit writes
// remain owned by domain event consumers and authentication code, preventing
// an admin request from rewriting its own history.
type AuditReader interface {
	List(context.Context, int) ([]audit.Event, error)
}

// WithAuditReader adds read-only audit visibility to the admin surface while
// keeping the audit writer owned by the application composition root.
func WithAuditReader(reader AuditReader) ServerOption {
	return func(server *Server) { server.audit = reader }
}

// RelaySessionIssuer mints a short-lived ticket bound to one device, one peer,
// and one session. The relay verifies the ticket locally and never calls
// control.
type RelaySessionIssuer interface {
	IssueForPeer(sessionID, deviceID, destinationDeviceID string, ttl time.Duration) (string, error)
}

// RelayPeerAuthorizer is evaluated after both device credentials are checked.
// The composition root can bind ticket issuance to the latest signed topology
// without making the HTTP package depend on snapshot persistence.
type RelayPeerAuthorizer func(context.Context, devices.Device, devices.Device) bool

func WithRelaySessionIssuer(issuer RelaySessionIssuer, relayURL string, ttl time.Duration) ServerOption {
	return func(server *Server) {
		server.relayIssuer = issuer
		server.relayURL = strings.TrimRight(relayURL, "/")
		server.relayTTL = ttl
	}
}

// WithRelayUDPAddress exposes the separate raw UDP ingress returned to nodes
// that support the versioned udp_pair_v1 transport. It is intentionally
// optional so older deployments can continue using the WebSocket bridge.
func WithRelayUDPAddress(address string) ServerOption {
	return func(server *Server) { server.relayUDPAddress = strings.TrimSpace(address) }
}

// WithRelayPeerAuthorizer adds a policy/topology check for relay tickets.
// Leaving it unset preserves the lower-level role check used by isolated HTTP
// tests and legacy deployments; production composition supplies it whenever a
// trusted snapshot service is configured.
func WithRelayPeerAuthorizer(authorizer RelayPeerAuthorizer) ServerOption {
	return func(server *Server) { server.relayPeerAuthorizer = authorizer }
}

func WithRouteService(service RouteService) ServerOption {
	return func(server *Server) { server.routes = service }
}

type PolicyService interface {
	Replace(context.Context, []policy.Rule) (policy.Snapshot, error)
	ReplaceIfRevision(context.Context, uint64, []policy.Rule) (policy.Snapshot, error)
	Latest(context.Context) (policy.Snapshot, error)
}

func WithPolicyService(service PolicyService) ServerOption {
	return func(server *Server) { server.policy = service }
}

func WithCoordinationHandler(handler http.Handler) ServerOption {
	return func(server *Server) { server.coordination = handler }
}

func WithMetricsHandler(handler http.Handler) ServerOption {
	return func(server *Server) { server.metrics = handler }
}

// WithReadiness lets the composition root expose real dependency health without
// coupling the HTTP package to PostgreSQL, migrations, or a specific runtime.
func WithReadiness(check func(context.Context) error) ServerOption {
	return func(server *Server) { server.ready = check }
}

// ServiceCatalog is the HTTP-facing contract for named services and access
// profiles. It intentionally contains no persistence methods.
type ServiceCatalog interface {
	Create(context.Context, controlservices.Service) (controlservices.Service, error)
	List(context.Context) ([]controlservices.Service, error)
	ListForDevice(context.Context, string) ([]controlservices.Service, error)
	CreateProfile(context.Context, controlservices.AccessProfile) (controlservices.AccessProfile, error)
	Profiles(context.Context) ([]controlservices.AccessProfile, error)
}

// InviteService accepts a signed device proof without exposing the companion's
// short code to the control plane. Approval remains a local companion action.
type InviteService interface {
	SubmitProof(context.Context, invite.SignedPermit, invite.Proof) error
	Get(context.Context, string) (controlinvites.Record, error)
	ApproveSigned(context.Context, invite.SignedApproval) (controlinvites.ApprovalResult, error)
}

func WithInviteService(service InviteService) ServerOption {
	return func(server *Server) { server.invites = service }
}

type SnapshotService interface {
	Publish(context.Context, snapshot.Envelope) error
	Latest(context.Context) (snapshot.Envelope, error)
}

// SnapshotBroadcaster is separate from SnapshotService because persistence
// and live delivery have different failure semantics: a committed snapshot
// must remain available even when no coordination peer is connected.
type SnapshotBroadcaster interface {
	BroadcastSnapshot(context.Context, snapshot.Envelope)
}

func WithSnapshotService(service SnapshotService) ServerOption {
	return func(server *Server) { server.snapshots = service }
}

func WithSnapshotBroadcaster(broadcaster SnapshotBroadcaster) ServerOption {
	return func(server *Server) { server.snapshotBroadcaster = broadcaster }
}

// WithCompanionRootKey enables the challenge-bound snapshot read used by the
// trusted Mac companion. It is separate from browser admin auth because the
// companion holds the root private key, not a reusable web session.
func WithCompanionRootKey(publicKey ed25519.PublicKey) ServerOption {
	return func(server *Server) {
		server.companionRoot = append(ed25519.PublicKey(nil), publicKey...)
		server.companionChallenges = newCompanionChallengeStore()
	}
}

// WithTrustedProxyCIDRs permits forwarded client addresses only when the
// immediate peer belongs to one of these explicitly configured proxies.
func WithTrustedProxyCIDRs(prefixes []netip.Prefix) ServerOption {
	return func(server *Server) { server.trustedProxy = append([]netip.Prefix(nil), prefixes...) }
}

func WithServiceCatalog(catalog ServiceCatalog) ServerOption {
	return func(server *Server) { server.services = catalog }
}

func NewServer(deviceService DeviceService, authorizer Authorizer, options ...ServerOption) *Server {
	server := &Server{
		devices:       deviceService,
		authorizer:    authorizer,
		logger:        slog.Default(),
		apiLimiter:    NewRateLimiter(120, time.Minute, nil),
		authLimiter:   NewRateLimiter(5, time.Minute, nil),
		deviceLimiter: NewRateLimiter(10, time.Minute, nil),
	}
	for _, option := range options {
		option(server)
	}
	return server
}

func (s *Server) Handler() http.Handler {
	return NewRouter(s)
}
