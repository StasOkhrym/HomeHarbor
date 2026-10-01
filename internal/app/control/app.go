// Package control assembles the control-plane runtime. Domain modules expose
// narrow interfaces; this package is the only place that wires concrete
// PostgreSQL, Watermill, HTTP, and observability implementations together.
package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill/pubsub/gochannel"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"

	workflowstorage "github.com/sokhrym/go-tunnels/internal/app/control/storage"
	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	auditstorage "github.com/sokhrym/go-tunnels/internal/control/audit/storage"
	"github.com/sokhrym/go-tunnels/internal/control/coordination"
	"github.com/sokhrym/go-tunnels/internal/control/devices"
	devicesstorage "github.com/sokhrym/go-tunnels/internal/control/devices/storage"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
	"github.com/sokhrym/go-tunnels/internal/control/identity"
	identityredis "github.com/sokhrym/go-tunnels/internal/control/identity/redis"
	identitystorage "github.com/sokhrym/go-tunnels/internal/control/identity/storage"
	controlinvites "github.com/sokhrym/go-tunnels/internal/control/invites"
	invitesstorage "github.com/sokhrym/go-tunnels/internal/control/invites/storage"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
	policystorage "github.com/sokhrym/go-tunnels/internal/control/policy/storage"
	controlroutes "github.com/sokhrym/go-tunnels/internal/control/routes"
	routesstorage "github.com/sokhrym/go-tunnels/internal/control/routes/storage"
	controlservices "github.com/sokhrym/go-tunnels/internal/control/services"
	servicesstorage "github.com/sokhrym/go-tunnels/internal/control/services/storage"
	controlsnapshots "github.com/sokhrym/go-tunnels/internal/control/snapshots"
	snapshotsstorage "github.com/sokhrym/go-tunnels/internal/control/snapshots/storage"
	"github.com/sokhrym/go-tunnels/internal/platform/config"
	"github.com/sokhrym/go-tunnels/internal/platform/events"
	"github.com/sokhrym/go-tunnels/internal/platform/lifecycle"
	"github.com/sokhrym/go-tunnels/internal/platform/redissecurity"
	"github.com/sokhrym/go-tunnels/internal/relay"
	networksnapshot "github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/migrations"
)

// App owns the control-plane process and its shutdown order. Dependencies are
// closed in reverse ownership order so consumers stop before their stores.
type App struct {
	server        *http.Server
	metricsServer *http.Server
	pool          *pgxpool.Pool
	bus           *gochannel.GoChannel
	logger        *slog.Logger
	redis         *redis.Client
	auditPipeline *events.AuditPipeline
	coordination  *coordination.Handler
}

var _ lifecycle.Component = (*App)(nil)

// New validates dependencies and builds the HTTP runtime. Migration ownership
// intentionally stays in the dedicated migrate process rather than here or in
// HTTP readiness: only one process should mutate the database schema.
func New(ctx context.Context, cfg config.Control, logger *slog.Logger) (*App, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Database.Driver != "" && cfg.Database.Driver != "postgres" {
		return nil, errors.New("unsupported database driver")
	}
	if cfg.Redis.URL == "" || cfg.Redis.Password == "" {
		return nil, errors.New("redis endpoint and resolved password are required")
	}
	redisOptions, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, errors.New("invalid Redis endpoint")
	}
	redisOptions.Password = cfg.Redis.Password
	redisOptions.DialTimeout = time.Second
	redisOptions.ReadTimeout = time.Second
	redisOptions.WriteTimeout = time.Second
	redisClient := redis.NewClient(redisOptions)
	if err := redisClient.Ping(ctx).Err(); err != nil {
		_ = redisClient.Close()
		return nil, errors.New("redis security state unavailable")
	}
	keepRedis := false
	defer func() {
		if !keepRedis {
			_ = redisClient.Close()
		}
	}()
	securityState := redissecurity.New(redisClient, "go-tunnels:"+cfg.Networking.NetworkID)
	poolConfig, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, errors.Join(errors.New("parse database configuration"), err)
	}
	if cfg.Database.Password != "" {
		poolConfig.ConnConfig.Password = cfg.Database.Password
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, errors.Join(errors.New("connect database"), err)
	}
	closePool := func(err error) (*App, error) {
		pool.Close()
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return closePool(errors.Join(errors.New("ping database"), err))
	}
	bus := gochannel.NewGoChannel(gochannel.Config{PreserveContext: true}, watermill.NewSlogLogger(logger))
	closeBusAndPool := func(err error) (*App, error) {
		_ = bus.Close()
		pool.Close()
		return nil, err
	}
	auditSink := auditstorage.New(pool)
	auditPipeline := events.NewAuditPipeline(bus, auditSink)

	deviceService := devices.NewService(devicesstorage.New(pool, workflowstorage.AppendEvent), time.Now, nil)
	routeService := controlroutes.NewService(routesstorage.New(pool), time.Now)
	policyService := policy.NewService(policystorage.New(pool), policy.Compiler{})
	serviceCatalog := controlservices.NewService(
		servicesstorage.New(pool),
		time.Now,
		controlservices.WithDeviceActiveChecker(func(ctx context.Context, id string) (bool, error) {
			device, err := deviceService.Device(ctx, id)
			if err != nil {
				return false, err
			}
			return device.Status == devices.StatusActive, nil
		}),
	)
	peerAuthorization := func(_ context.Context, source, destination devices.Device) bool {
		return source.Status == devices.StatusActive && destination.Status == devices.StatusActive &&
			source.Role != destination.Role
	}
	var signedSnapshots *controlsnapshots.Service
	identityStore := identitystorage.New(pool)
	identityService := identity.NewService(
		identityStore,
		identityredis.NewSessions(redisClient, "go-tunnels:"+cfg.Networking.NetworkID, time.Now),
		time.Now,
		nil,
	)
	passkeyService, err := identity.NewPasskeyService(identity.PasskeyConfig{
		RPID:          cfg.Auth.RPID,
		RPOrigin:      cfg.Auth.RPOrigin,
		EncryptionKey: []byte(cfg.Auth.CeremonyEncryptionKey),
		CeremonyTTL:   cfg.Auth.CeremonyDuration(),
	}, identityStore, identityredis.NewCeremonies(securityState, time.Now), time.Now, nil)
	if err != nil {
		return closeBusAndPool(errors.Join(errors.New("configure passkeys"), err))
	}
	auth, err := httpapi.NewBrowserAuth(httpapi.BrowserAuthConfig{
		Origin:     cfg.Auth.RPOrigin,
		SigningKey: []byte(cfg.Auth.SessionSigningKey),
		SessionTTL: cfg.Auth.SessionDuration(),
		Auditor:    events.NewIdentityAuditor(auditSink, time.Now),
		SetupState: passkeyService,
	}, passkeyService, identityService)
	if err != nil {
		return closeBusAndPool(errors.Join(errors.New("configure browser authentication"), err))
	}

	serverOptions := []httpapi.ServerOption{
		httpapi.WithBrowserActionConfirmation(auth),
		httpapi.WithBrowserHandlers(
			auth.Handler(),
			auth.LoginHandler(),
			auth.LoginAssetHandler(),
			auth.AuthorizeMutation,
		),
		httpapi.WithSharedRateLimits(securityState),
		httpapi.WithRouteService(routeService),
		httpapi.WithPolicyService(policyService),
		httpapi.WithServiceCatalog(serviceCatalog),
		httpapi.WithAuditReader(auditSink),
		httpapi.WithReadiness(func(readinessCtx context.Context) error {
			if err := auditPipeline.Check(); err != nil {
				return err
			}
			if err := redisClient.Ping(readinessCtx).Err(); err != nil {
				return errors.New("redis security state unavailable")
			}
			if err := pool.Ping(readinessCtx); err != nil {
				return err
			}
			return migrations.Ready(readinessCtx, pool)
		}),
	}
	relayTTL, err := cfg.RelayDuration()
	if err != nil {
		return closeBusAndPool(errors.Join(errors.New("configure relay sessions"), err))
	}
	serverOptions = append(
		serverOptions,
		httpapi.WithRelaySessionIssuer(
			relay.TicketIssuer{Key: []byte(cfg.Relay.TicketKey)},
			cfg.Relay.PublicURL,
			relayTTL,
		),
		httpapi.WithRelayUDPAddress(cfg.Relay.PublicUDPAddress),
	)
	trustedProxyCIDRs := make([]netip.Prefix, 0, len(cfg.Security.TrustedProxyCIDRs))
	for _, value := range cfg.Security.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return closeBusAndPool(errors.Join(errors.New("parse trusted proxy CIDR"), err))
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, prefix)
	}
	serverOptions = append(serverOptions, httpapi.WithTrustedProxyCIDRs(trustedProxyCIDRs))
	if cfg.Security.RootPublicKeyFile != "" {
		rootPublic, err := loadRootPublicKey(cfg.Security.RootPublicKeyFile)
		if err != nil {
			return closeBusAndPool(errors.Join(errors.New("load trusted companion root key"), err))
		}
		if strings.TrimSpace(cfg.Networking.NetworkID) == "" {
			return closeBusAndPool(errors.New("networking.network_id is required when invite verification is enabled"))
		}
		signedSnapshots = controlsnapshots.NewService(snapshotsstorage.New(pool), rootPublic, cfg.Networking.NetworkID)
		inviteStore := invitesstorage.New(pool)
		activation := workflows.NewActivation(
			workflowstorage.NewActivationUnitOfWork(pool),
			inviteStore,
			signedSnapshots,
			securityState,
			rootPublic,
			cfg.Networking.NetworkID,
			time.Now,
			nil,
		)
		activationHandler := httpapi.NewActivationHandler(activation, activation)
		serverOptions = append(
			serverOptions,
			httpapi.WithInviteService(
				controlinvites.NewService(
					inviteStore,
					rootPublic,
					cfg.Networking.NetworkID,
					time.Now,
					controlinvites.WithApprovalWorkflow(activation),
				),
			),
			httpapi.WithActivationHandlers(activationHandler.Challenge, activationHandler.Claim),
			httpapi.WithSnapshotService(signedSnapshots),
			httpapi.WithCompanionRootKey(rootPublic),
			httpapi.WithSharedChallenges(sharedChallenges{store: securityState}),
		)
		// Candidate exchange must use the same signed topology as relay ticket
		// issuance. A role-only check would disclose endpoint candidates for a
		// client/gateway pair that has no approved route or ACL relationship.
		peerAuthorization = func(ctx context.Context, source, destination devices.Device) bool {
			return authorizeRelayPeer(ctx, signedSnapshots, rootPublic, cfg.Networking.NetworkID, source, destination)
		}
		serverOptions = append(serverOptions, httpapi.WithRelayPeerAuthorizer(peerAuthorization))
	}
	// Construct one coordination handler after all security dependencies are
	// known. The same instance owns live snapshot broadcasts and WebSocket
	// connections; creating a temporary handler earlier would silently strand
	// broadcasts on a hub that serves no production clients.
	coordinationHandler := coordination.NewHandlerWithHistory(
		deviceService,
		deviceService,
		signedSnapshots,
		[]string{cfg.Auth.RPOrigin},
		peerAuthorization,
	)
	if signedSnapshots != nil {
		serverOptions = append(serverOptions, httpapi.WithSnapshotBroadcaster(coordinationHandler))
	}
	serverOptions = append(
		serverOptions,
		httpapi.WithCoordinationHandler(coordinationHandler),
		httpapi.WithSnapshotHistoryHandler(http.HandlerFunc(coordinationHandler.ServeHistory)),
	)
	var metricsServer *http.Server
	if address := strings.TrimSpace(cfg.Observability.MetricsAddress); address != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", promhttp.Handler())
		metricsServer = &http.Server{
			Addr:              address,
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    64 << 10,
		}
	}
	handler := httpapi.NewServer(
		deviceService,
		auth,
		serverOptions...,
	).Handler()

	keepRedis = true
	return &App{
		coordination:  coordinationHandler,
		redis:         redisClient,
		auditPipeline: auditPipeline,
		pool:          pool,
		bus:           bus,
		logger:        logger,
		metricsServer: metricsServer,
		server: &http.Server{
			Addr:              cfg.Server.ListenAddress,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 << 10,
		},
	}, nil
}

// authorizeRelayPeer makes relay ticket issuance depend on the same signed
// topology consumed by nodes. A role check alone would let an authenticated
// device ask the relay to pair with every active gateway, even when no route
// or ACL grants that relationship. Verifying the envelope again at this
// boundary also prevents a corrupt or tampered metadata store from becoming a
// source of relay authorization without the trusted companion signature.
type signedSnapshotReader interface {
	Latest(context.Context) (networksnapshot.Envelope, error)
}

func authorizeRelayPeer(
	ctx context.Context,
	snapshots signedSnapshotReader,
	rootPublic ed25519.PublicKey,
	networkID string,
	source, destination devices.Device,
) bool {
	if snapshots == nil {
		return false
	}
	envelope, err := snapshots.Latest(ctx)
	if err != nil {
		return false
	}
	if _, err := networksnapshot.Verify(envelope, rootPublic, networkID); err != nil {
		return false
	}
	value, err := networksnapshot.Decode(envelope)
	if err != nil {
		return false
	}
	var sourceDevice, destinationDevice *networksnapshot.Device
	for index := range value.Devices {
		device := &value.Devices[index]
		switch device.ID {
		case source.ID:
			sourceDevice = device
		case destination.ID:
			destinationDevice = device
		}
	}
	if sourceDevice == nil || destinationDevice == nil || sourceDevice.Role != string(source.Role) ||
		destinationDevice.Role != string(destination.Role) ||
		sourceDevice.Role == destinationDevice.Role {
		return false
	}
	clientID, gatewayID := source.ID, destination.ID
	if source.Role == devices.RoleGateway {
		clientID, gatewayID = destination.ID, source.ID
	}
	if source.Role != devices.RoleClient && source.Role != devices.RoleGateway {
		return false
	}
	if destination.Role != devices.RoleClient && destination.Role != devices.RoleGateway {
		return false
	}
	for _, route := range value.Routes {
		if route.GatewayID != gatewayID {
			continue
		}
		routePrefix, routeErr := netip.ParsePrefix(route.Prefix)
		if routeErr != nil {
			continue
		}
		for _, acl := range value.ACL {
			if acl.SourceDeviceID != clientID {
				continue
			}
			aclPrefix, aclErr := netip.ParsePrefix(acl.Destination)
			if aclErr == nil && prefixesOverlap(routePrefix, aclPrefix) {
				return true
			}
		}
	}
	return false
}

func prefixesOverlap(left, right netip.Prefix) bool {
	return left.Contains(right.Addr()) || right.Contains(left.Addr())
}

func loadRootPublicKey(path string) (ed25519.PublicKey, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value = []byte(strings.TrimSpace(string(value)))
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(string(value)); decodeErr == nil {
		value = decoded
	}
	if len(value) != ed25519.PublicKeySize {
		return nil, errors.New("trusted companion root public key must be 32 raw or base64url bytes")
	}
	return ed25519.PublicKey(append([]byte(nil), value...)), nil
}

// Run serves HTTP until the context is cancelled. Shutdown has a bounded
// deadline so a stuck client cannot prevent the process from exiting.
func (a *App) Run(ctx context.Context) error {
	// Run owns every dependency even if listener creation fails. Workers stop
	// before stores close; a deferred cleanup cannot race a still-running sink.
	defer a.pool.Close()
	defer func() { _ = a.redis.Close() }()
	defer func() { _ = a.bus.Close() }()
	listener, err := net.Listen("tcp", a.server.Addr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	var metricsListener net.Listener
	if a.metricsServer != nil {
		metricsListener, err = net.Listen("tcp", a.metricsServer.Addr)
		if err != nil {
			return err
		}
		defer func() { _ = metricsListener.Close() }()
	}
	components := []lifecycle.Component{
		a.coordination,
		a.auditPipeline,
		lifecycle.Func(func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return nil
			case <-a.auditPipeline.Ready():
			}
			return events.RunOutboxDispatcher(ctx, a.pool, a.auditPipeline, a.logger)
		}),
		lifecycle.Func(func(ctx context.Context) error { return serveHTTP(ctx, a.server, listener) }),
	}
	if a.metricsServer != nil {
		components = append(components, lifecycle.Func(func(ctx context.Context) error {
			return serveHTTP(ctx, a.metricsServer, metricsListener)
		}))
	}
	return lifecycle.Run(ctx, components...)
}
