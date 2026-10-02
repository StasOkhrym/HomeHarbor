package httpapi

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/control/audit"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	controlinvites "github.com/StasOkhrym/homeharbor/internal/control/invites"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
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
	Advertise(
		context.Context,
		controlroutes.AdvertisementRequest,
	) (controlroutes.Advertisement, error)
	Approve(context.Context, string) error
	Reject(context.Context, string) error
	List(context.Context) ([]controlroutes.Advertisement, error)
}

// AuditReader is deliberately read-only at the HTTP boundary. Audit writes
// remain owned by domain event consumers and authentication code, preventing
// an admin request from rewriting its own history.
type AuditReader interface {
	List(context.Context, int) ([]audit.Event, error)
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

type PolicyService interface {
	Replace(context.Context, []policy.Rule) (policy.Snapshot, error)
	ReplaceIfRevision(context.Context, uint64, []policy.Rule) (policy.Snapshot, error)
	Latest(context.Context) (policy.Snapshot, error)
}

// ServiceCatalog is the HTTP-facing contract for named services and access
// profiles. It intentionally contains no persistence methods.
type ServiceCatalog interface {
	Create(context.Context, controlservices.Service) (controlservices.Service, error)
	List(context.Context) ([]controlservices.Service, error)
	ListForDevice(context.Context, string) ([]controlservices.Service, error)
	CreateProfile(
		context.Context,
		controlservices.AccessProfile,
	) (controlservices.AccessProfile, error)
	Profiles(context.Context) ([]controlservices.AccessProfile, error)
}

// InviteService accepts a signed device proof without exposing the companion's
// short code to the control plane. Approval remains a local companion action.
type InviteService interface {
	SubmitProof(context.Context, invite.SignedPermit, invite.Proof) error
	Get(context.Context, string) (controlinvites.Record, error)
	ApproveSigned(context.Context, invite.SignedApproval) (controlinvites.ApprovalResult, error)
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

func (s *Server) Handler() http.Handler {
	return NewRouter(s)
}
