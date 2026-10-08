package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/StasOkhrym/homeharbor/internal/acl"
	auditstorage "github.com/StasOkhrym/homeharbor/internal/control/audit/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/coordination"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicesstorage "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/httpapi"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identityredis "github.com/StasOkhrym/homeharbor/internal/control/identity/redis"
	identitystorage "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	controlinvites "github.com/StasOkhrym/homeharbor/internal/control/invites"
	invitesstorage "github.com/StasOkhrym/homeharbor/internal/control/invites/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/policy"
	policystorage "github.com/StasOkhrym/homeharbor/internal/control/policy/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/profiles"
	profilesstorage "github.com/StasOkhrym/homeharbor/internal/control/profiles/storage"
	controlroutes "github.com/StasOkhrym/homeharbor/internal/control/routes"
	routesstorage "github.com/StasOkhrym/homeharbor/internal/control/routes/storage"
	controlservices "github.com/StasOkhrym/homeharbor/internal/control/services"
	servicesstorage "github.com/StasOkhrym/homeharbor/internal/control/services/storage"
	controlsnapshots "github.com/StasOkhrym/homeharbor/internal/control/snapshots"
	snapshotsstorage "github.com/StasOkhrym/homeharbor/internal/control/snapshots/storage"
	workflowstorage "github.com/StasOkhrym/homeharbor/internal/control/transactions"
	"github.com/StasOkhrym/homeharbor/internal/control/workflows"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	"github.com/StasOkhrym/homeharbor/internal/platform/events"
	"github.com/StasOkhrym/homeharbor/internal/platform/redissecurity"
	"github.com/StasOkhrym/homeharbor/internal/relay"
	"github.com/StasOkhrym/homeharbor/migrations"
)

func buildHTTP(
	cfg config.Control,
	logger *slog.Logger,
	stores *runtimeStores,
) (*httpapi.Server, *coordination.Handler, *events.AuditPipeline, error) {
	pool, redisClient, bus := stores.pool, stores.redis, stores.bus
	securityState := redissecurity.New(redisClient, "homeharbor:"+cfg.Networking.NetworkID)
	auditSink := auditstorage.New(pool)
	auditPipeline := events.NewAuditPipeline(bus, auditSink)

	deviceService := devices.NewService(
		devicesstorage.New(pool, workflowstorage.AppendEvent),
		time.Now,
		nil,
		devices.WithCredentialTTL(cfg.Runtime.CredentialTTL),
	)
	routeService := controlroutes.NewService(routesstorage.New(pool), time.Now)
	policyService := policy.NewService(policystorage.New(pool), acl.Compiler{})
	serviceCatalog := controlservices.NewService(servicesstorage.New(pool), time.Now)
	profileService := profiles.NewService(
		profilesstorage.New(pool), serviceCatalog, time.Now,
		func(ctx context.Context, id string) (bool, error) {
			device, err := deviceService.Device(ctx, id)
			if err != nil {
				return false, err
			}
			return device.Status == devices.StatusActive, nil
		},
	)

	peerAuthorization := func(_ context.Context, source, destination devices.Device) bool {
		return source.Status == devices.StatusActive &&
			destination.Status == devices.StatusActive &&
			source.Role != destination.Role
	}
	var signedSnapshots *controlsnapshots.Service
	identityStore := identitystorage.New(pool)
	sessionStore, err := identityredis.NewSessions(
		redisClient,
		"homeharbor:"+cfg.Networking.NetworkID,
		time.Now,
		cfg.Runtime.RedisTimeout,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	identityService := identity.NewService(
		identityStore,
		sessionStore,
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
		return nil, nil, nil, errors.Join(errors.New("configure passkeys"), err)
	}
	auth, err := httpapi.NewBrowserAuth(httpapi.BrowserAuthConfig{
		Origin:     cfg.Auth.RPOrigin,
		SigningKey: []byte(cfg.Auth.SessionSigningKey),
		SessionTTL: cfg.Auth.SessionDuration(),
		Auditor:    events.NewIdentityAuditor(auditSink, time.Now),
		SetupState: passkeyService,
	}, passkeyService, identityService)
	if err != nil {
		return nil, nil, nil, errors.Join(errors.New("configure browser authentication"), err)
	}

	deps := httpapi.Dependencies{
		Resources: httpapi.ResourceDependencies{
			Devices: deviceService,
			Recovery: workflows.NewCredentialRecovery(
				deviceService,
				sharedChallenges{store: securityState, timeout: cfg.Runtime.RedisTimeout},
				cfg.Networking.NetworkID,
				time.Now,
				nil,
			),
			Routes:   routeService,
			Policy:   policyService,
			Services: serviceCatalog,
			Profiles: profileService,
			Audit:    auditSink,
		},
		Browser: httpapi.BrowserDependencies{
			API:                auth.Handler(),
			LoginPage:          auth.LoginHandler(),
			LoginAsset:         auth.LoginAssetHandler(),
			MutationAuthorizer: auth.AuthorizeMutation,
			ActionConfirmation: auth,
		},
		Security: httpapi.SecurityDependencies{
			Authorizer: auth,
			APILimiter: httpapi.NewRateLimiter(cfg.Runtime.APIPerMinute, time.Minute, nil),
			AuthLimiter: httpapi.NewSharedRateLimiter(
				securityState,
				"auth",
				cfg.Runtime.AuthPerMinute,
				time.Minute,
			),
			DeviceLimiter: httpapi.NewSharedRateLimiter(
				securityState,
				"onboarding",
				cfg.Runtime.OnboardingPerMinute,
				time.Minute,
			),
			CompanionTTL: cfg.Runtime.CompanionTTL,
			StoreTimeout: cfg.Runtime.RedisTimeout,
		},
		Observability: httpapi.ObservabilityDependencies{
			Logger: logger,
			Ready: func(readinessCtx context.Context) error {
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
			},
		},
	}
	relayTTL, err := cfg.RelayDuration()
	if err != nil {
		return nil, nil, nil, errors.Join(errors.New("configure relay sessions"), err)
	}
	deps.Relay = httpapi.RelayDependencies{
		Issuer:     relay.TicketIssuer{Key: []byte(cfg.Relay.TicketKey)},
		URL:        cfg.Relay.PublicURL,
		UDPAddress: cfg.Relay.PublicUDPAddress,
		TTL:        relayTTL,
	}
	trustedProxyCIDRs := make([]netip.Prefix, 0, len(cfg.Security.TrustedProxyCIDRs))
	for _, value := range cfg.Security.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, nil, nil, errors.Join(errors.New("parse trusted proxy CIDR"), err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, prefix)
	}
	deps.Security.TrustedProxyCIDRs = trustedProxyCIDRs
	if cfg.Security.RootPublicKeyFile != "" {
		rootPublic, err := loadRootPublicKey(cfg.Security.RootPublicKeyFile)
		if err != nil {
			return nil, nil, nil, errors.Join(errors.New("load trusted companion root key"), err)
		}
		if strings.TrimSpace(cfg.Networking.NetworkID) == "" {
			return nil, nil, nil, errors.New(
				"networking.network_id is required when invite verification is enabled",
			)
		}
		signedSnapshots = controlsnapshots.NewService(
			snapshotsstorage.New(pool),
			rootPublic,
			cfg.Networking.NetworkID,
		)
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
			workflows.WithLifetimes(cfg.Runtime.ClaimTTL, cfg.Runtime.CredentialTTL),
		)
		activationHandler := httpapi.NewActivationHandler(activation, activation)
		deps.Resources.Invites = controlinvites.NewService(
			inviteStore,
			rootPublic,
			cfg.Networking.NetworkID,
			time.Now,
			controlinvites.WithApprovalWorkflow(activation),
		)
		deps.Activation = httpapi.ActivationDependencies{
			Challenge: activationHandler.Challenge,
			Claim:     activationHandler.Claim,
		}
		deps.Resources.Snapshots = signedSnapshots
		deps.Security.RootPublicKey = rootPublic
		deps.Security.Challenges = sharedChallenges{
			store:   securityState,
			timeout: cfg.Runtime.RedisTimeout,
		}
		// Candidate exchange must use the same signed topology as relay ticket
		// issuance. A role-only check would disclose endpoint candidates for a
		// client/gateway pair that has no approved route or ACL relationship.
		peerAuthorization = func(ctx context.Context, source, destination devices.Device) bool {
			return authorizeRelayPeer(
				ctx,
				signedSnapshots,
				rootPublic,
				cfg.Networking.NetworkID,
				source,
				destination,
			)
		}
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
		deps.Resources.SnapshotBroadcaster = coordinationHandler
	}
	deps.Resources.InvalidateDevice = coordinationHandler.InvalidateDevice
	deps.Coordination = coordinationHandler
	deps.SnapshotHistory = http.HandlerFunc(coordinationHandler.ServeHistory)
	deps.Relay.PeerAuthorizer = peerAuthorization
	httpServer, err := httpapi.NewServer(deps)
	if err != nil {
		return nil, nil, nil, errors.Join(errors.New("configure HTTP dependencies"), err)
	}
	return httpServer, coordinationHandler, auditPipeline, nil
}

func newMetricsServer(cfg config.Control) *http.Server {
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

	return metricsServer
}
