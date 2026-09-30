package httpapi

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sokhrym/go-tunnels/internal/control/audit"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	controlnetwork "github.com/sokhrym/go-tunnels/internal/control/routes"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/protocol"
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
	IsAdmin(context.Context, *http.Request) bool
}

// Server composes optional module capabilities at the HTTP boundary. Domain
// services remain unaware of chi and continue to satisfy narrow interfaces.
type Server struct {
	devices             DeviceService
	network             NetworkService
	policy              PolicyService
	authorizer          Authorizer
	logger              *slog.Logger
	coordination        http.Handler
	metrics             http.Handler
	ready               func(context.Context) error
	apiLimiter          *RateLimiter
	authLimiter         *RateLimiter
	deviceLimiter       *RateLimiter
	services            ServiceCatalog
	audit               AuditReader
	invites             InviteService
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
}

type NetworkService interface {
	Advertise(context.Context, controlnetwork.AdvertisementRequest) (controlnetwork.Advertisement, error)
	Approve(context.Context, string) error
	Reject(context.Context, string) error
	List(context.Context) ([]controlnetwork.Advertisement, error)
}
type ServerOption func(*Server)

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

func WithNetworkService(service NetworkService) ServerOption {
	return func(server *Server) { server.network = service }
}

type PolicyService interface {
	Replace(context.Context, []policy.Rule) (policy.Snapshot, error)
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
	CreateProfile(context.Context, controlservices.AccessProfile) (controlservices.AccessProfile, error)
	Profiles(context.Context) ([]controlservices.AccessProfile, error)
}

// InviteService accepts a signed device proof without exposing the companion's
// short code to the control plane. Approval remains a local companion action.
type InviteService interface {
	SubmitProof(context.Context, invite.SignedPermit, invite.Proof) error
	Get(context.Context, string) (controlinvites.Record, error)
	ApproveSigned(context.Context, invite.SignedApproval) (controlinvites.ActivationResult, error)
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
	server := &Server{devices: deviceService, authorizer: authorizer, logger: slog.Default(), apiLimiter: NewRateLimiter(120, time.Minute, nil), authLimiter: NewRateLimiter(5, time.Minute, nil), deviceLimiter: NewRateLimiter(10, time.Minute, nil)}
	for _, option := range options {
		option(server)
	}
	return server
}

func (s *Server) Handler() http.Handler {
	return NewRouter(s)
}

func (s *Server) latestPolicy(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.policy.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load policy")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) replacePolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Rules []policy.Rule `json:"rules"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	snapshot, err := s.policy.Replace(r.Context(), input.Rules)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "invalid_policy", "policy rules are invalid")
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	routes := []controlnetwork.Advertisement{}
	if s.network != nil {
		routes, _ = s.network.List(r.Context())
	}
	services := []controlservices.Service{}
	profiles := []controlservices.AccessProfile{}
	if s.services != nil {
		services, _ = s.services.List(r.Context())
		profiles, _ = s.services.Profiles(r.Context())
	}
	auditEvents := []audit.Event{}
	if s.audit != nil {
		auditEvents, _ = s.audit.List(r.Context(), defaultAuditLimit)
	}
	policyJSON := "[]"
	if s.policy != nil {
		if current, policyErr := s.policy.Latest(r.Context()); policyErr == nil {
			if encoded, marshalErr := json.MarshalIndent(current.Rules, "", "  "); marshalErr == nil {
				policyJSON = string(encoded)
			}
		}
	}
	if err := adminTemplate.Execute(w, map[string]any{
		"Devices":    list,
		"Routes":     routes,
		"Services":   services,
		"Profiles":   profiles,
		"Audit":      auditEvents,
		"PolicyJSON": policyJSON,
		"CSRF":       csrfFormToken(r),
		"Notice":     r.URL.Query().Get("notice"),
	}); err != nil {
		s.logger.Error("render admin", "error", err)
	}
}

func (s *Server) advertiseRoute(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID              string `json:"id"`
		GatewayDeviceID string `json:"gateway_device_id"`
		Prefix          string `json:"prefix"`
		Resolver        string `json:"resolver"`
		DomainSuffix    string `json:"domain_suffix"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	prefix, err := netip.ParsePrefix(input.Prefix)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid prefix")
		return
	}
	resolver, err := netip.ParseAddr(input.Resolver)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid resolver")
		return
	}
	item, err := s.network.Advertise(r.Context(), controlnetwork.AdvertisementRequest{ID: input.ID, GatewayDeviceID: input.GatewayDeviceID, Prefix: prefix, Resolver: resolver, DomainSuffix: input.DomainSuffix})
	if err != nil {
		if errors.Is(err, controlnetwork.ErrInvalidAdvertisement) {
			writeErrorCode(w, http.StatusBadRequest, "invalid_route", "route advertisement is invalid")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not advertise route")
		}
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	items, err := s.network.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"routes": items})
}

func (s *Server) approveRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Approve(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, controlnetwork.ErrAdvertisementNotFound) {
			writeErrorCode(w, http.StatusNotFound, "route_not_found", "route advertisement not found")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not approve route")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rejectRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.network.Reject(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, controlnetwork.ErrAdvertisementNotFound) {
			writeErrorCode(w, http.StatusNotFound, "route_not_found", "route advertisement not found")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not reject route")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorized := s.authorizer != nil && s.authorizer.IsAdmin(r.Context(), r)
		if authorized && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if mutations, ok := s.authorizer.(interface {
				AuthorizeMutation(context.Context, *http.Request) bool
			}); ok {
				authorized = mutations.AuthorizeMutation(r.Context(), r)
			}
		}
		if !authorized {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Role       devices.Role `json:"role"`
		TTLSeconds int64        `json:"ttl_seconds"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	token, err := s.devices.IssueEnrollmentToken(r.Context(), input.Role, time.Duration(input.TTLSeconds)*time.Second)
	if err != nil {
		if errors.Is(err, devices.ErrInvalidTokenRequest) {
			writeErrorCode(w, http.StatusBadRequest, "invalid_request", "enrollment token request is invalid")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not create enrollment token")
		}
		return
	}
	writeJSON(w, http.StatusCreated, token)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	var input devices.EnrollRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	device, err := s.devices.Enroll(r.Context(), input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, devices.ErrInvalidEnrollmentToken) {
			status = http.StatusUnauthorized
			writeErrorCode(w, status, "invalid_enrollment_token", "enrollment token is invalid or expired")
		} else if errors.Is(err, devices.ErrInvalidEnrollment) {
			writeErrorCode(w, status, "invalid_request", "enrollment request is invalid")
		} else {
			writeErrorCode(w, http.StatusInternalServerError, "internal_error", "could not enroll device")
		}
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	credential := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	device, err := s.devices.Authenticate(r.Context(), credential)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid device credential")
		return
	}
	rotated, err := s.devices.RotateCredential(r.Context(), device.ID, credential)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device credential expired or revoked")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"credential": rotated})
}

func (s *Server) issueRelaySession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID           string `json:"session_id"`
		DestinationDeviceID string `json:"destination_device_id"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	credential := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	source, err := s.devices.Authenticate(r.Context(), credential)
	if err != nil || source.Status != devices.StatusActive {
		writeError(w, http.StatusUnauthorized, "device authentication required")
		return
	}
	destination, err := s.devices.Device(r.Context(), strings.TrimSpace(input.DestinationDeviceID))
	if err != nil || destination.Status != devices.StatusActive || destination.ID == source.ID {
		writeError(w, http.StatusForbidden, "destination device is unavailable")
		return
	}
	// MVP relay sessions connect one external client to one LAN gateway. Do
	// not accidentally turn the relay into an unrestricted device mesh before
	// an explicit peer-policy model exists.
	if source.Role == destination.Role || (source.Role != devices.RoleClient && source.Role != devices.RoleGateway) {
		writeError(w, http.StatusForbidden, "device peer role is not allowed")
		return
	}
	if s.relayPeerAuthorizer != nil && !s.relayPeerAuthorizer(r.Context(), source, destination) {
		writeError(w, http.StatusForbidden, "device peer is not authorized")
		return
	}
	if strings.TrimSpace(input.SessionID) == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if s.relayTTL <= 0 {
		writeError(w, http.StatusServiceUnavailable, "relay sessions are unavailable")
		return
	}
	ticket, err := s.relayIssuer.IssueForPeer(input.SessionID, source.ID, destination.ID, s.relayTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue relay session")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		SessionID           string `json:"session_id"`
		DeviceID            string `json:"device_id"`
		DestinationDeviceID string `json:"destination_device_id"`
		RelayURL            string `json:"relay_url"`
		RelayUDPAddress     string `json:"relay_udp_address,omitempty"`
		Ticket              string `json:"ticket"`
		ExpiresInSeconds    int64  `json:"expires_in_seconds"`
	}{input.SessionID, source.ID, destination.ID, s.relayURL, s.relayUDPAddress, ticket, int64(s.relayTTL / time.Second)})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.devices.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": list})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	// This mutation revokes control-plane credentials only. The signed snapshot
	// is owned by the trusted companion, so the companion must publish a
	// separate exact removal for an already-connected node to lose data-plane
	// access during a later control-plane outage.
	if err := s.devices.Revoke(r.Context(), r.PathValue("id")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, devices.ErrDeviceNotFound) {
			status = http.StatusNotFound
			writeErrorCode(w, status, "device_not_found", "device not found")
		} else {
			writeErrorCode(w, status, "internal_error", "could not revoke device credentials")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) submitInviteProof(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Permit invite.SignedPermit `json:"permit"`
		Proof  invite.Proof        `json:"proof"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.invites.SubmitProof(r.Context(), input.Permit, input.Proof); err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite proof")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": string(controlinvites.StatusPending)})
}

func (s *Server) getInvite(w http.ResponseWriter, r *http.Request) {
	record, err := s.invites.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "invite not found")
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (s *Server) approveInvite(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Approval invite.SignedApproval `json:"approval"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := s.invites.ApproveSigned(r.Context(), input.Approval)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid invite approval")
		return
	}
	// The response contains the credential exactly once. The pending proof and
	// root approval are deliberately omitted because neither is needed by the
	// enrolling node after the transaction commits.
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) publishSnapshot(w http.ResponseWriter, r *http.Request) {
	var envelope snapshot.Envelope
	if !decodeJSON(w, r, &envelope) {
		return
	}
	if err := s.snapshots.Publish(r.Context(), envelope); err != nil {
		writeError(w, http.StatusBadRequest, "invalid signed snapshot")
		return
	}
	if s.snapshotBroadcaster != nil {
		s.snapshotBroadcaster.BroadcastSnapshot(r.Context(), envelope)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) latestSnapshot(w http.ResponseWriter, r *http.Request) {
	envelope, err := s.snapshots.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "signed snapshot unavailable")
		return
	}
	writeJSON(w, http.StatusOK, envelope)
}

func (s *Server) issueCompanionChallenge(w http.ResponseWriter, r *http.Request) {
	nonce, expiresAt, err := s.companionChallenges.issue(time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "companion challenge unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"nonce": nonce, "expires_at": expiresAt})
}

func (s *Server) companionSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.companionChallenges == nil || len(s.companionRoot) != ed25519.PublicKeySize {
		writeError(w, http.StatusNotFound, "companion access is not configured")
		return
	}
	nonce := r.Header.Get("X-Go-Tunnels-Companion-Nonce")
	keyID := r.Header.Get("X-Go-Tunnels-Companion-Key-ID")
	signature, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Go-Tunnels-Companion-Signature"))
	if err != nil || protocol.VerifyCompanionRequest(http.MethodGet, companionSnapshotPath, nonce, keyID, signature, s.companionRoot) != nil || !s.companionChallenges.consume(nonce, time.Now().UTC()) {
		writeError(w, http.StatusUnauthorized, "invalid companion request")
		return
	}
	envelope, err := s.snapshots.Latest(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "signed snapshot unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, envelope)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeErrorCode(w, status, errorCode(status), message)
}

func writeErrorCode(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "error": message})
}

func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "request_too_large"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusServiceUnavailable:
		return "unavailable"
	default:
		return "internal_error"
	}
}

func recoverMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if value := recover(); value != nil {
					// Panic values can contain request-derived secrets or database
					// details. Keep the log useful for alerting without turning it into
					// a second credential or internal-error disclosure channel.
					logger.Error("HTTP panic", "panic_type", fmt.Sprintf("%T", value))
					writeError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

//go:embed templates/admin.html
var adminPage []byte

//go:embed static/admin.css
var adminCSS []byte

var adminTemplate = template.Must(template.New("admin").Parse(string(adminPage)))
