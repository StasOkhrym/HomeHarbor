package control

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	netmail "net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	redisclient "github.com/redis/go-redis/v9"

	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	identitypg "github.com/StasOkhrym/homeharbor/internal/control/identity/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/notifications"
	notificationpg "github.com/StasOkhrym/homeharbor/internal/control/notifications/storage"
	"github.com/StasOkhrym/homeharbor/internal/platform/config"
	testpostgres "github.com/StasOkhrym/homeharbor/internal/testutil/postgres"
	authenticator "github.com/StasOkhrym/homeharbor/internal/testutil/webauthn"
	websession "github.com/StasOkhrym/homeharbor/internal/web/session"
	"github.com/StasOkhrym/homeharbor/migrations"
)

const (
	journeyOrigin   = "https://example.com"
	journeyPassword = "fixture only long password"
)

// This is an HTTP/SQL/Redis/SMTP acceptance test, not a native browser or hardware
// passkey check. It must run only in an explicitly owned combined capture fixture.
func TestPostgresRedisMailpitAccountJourney(t *testing.T) {
	if os.Getenv("TEST_ACCOUNT_JOURNEY") != "1" {
		t.Skip("owned combined account fixture required")
	}

	pool := testpostgres.OpenSchema(t)

	if err := migrations.Up(t.Context(), pool); err != nil {
		t.Fatal(err)
	}

	cfg := accountJourneyConfig(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mail, err := buildNotifications(cfg, notificationpg.New(pool), logger)
	if err != nil {
		t.Fatal("mail composition failed", err)
	}

	firstStores := &runtimeStores{pool: pool, redis: journeyRedis(t)}

	first := journeyServer(t, cfg, firstStores, mail, logger)

	// The second composition gets independent SQL and Redis connections, with the
	// same authority/key namespaces. Closing one later cannot affect the other.
	secondPool, err := pgxpool.NewWithConfig(t.Context(), pool.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(secondPool.Close)
	secondStores := &runtimeStores{pool: secondPool, redis: journeyRedis(t)}

	second := journeyServer(t, cfg, secondStores, mail, logger)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		keys, err := firstStores.redis.Keys(cleanup, "homeharbor:"+cfg.Networking.NetworkID+":*").
			Result()
		if err != nil {
			t.Error("owned Redis cleanup unavailable")

			return
		}

		if len(keys) > 0 {
			if err := firstStores.redis.Del(cleanup, keys...).Err(); err != nil {
				t.Error("owned Redis cleanup failed")
			}
		}
	})
	owner := first.client(t)
	ownerKey := authenticator.New(t, "example.com", journeyOrigin)

	ceremony := journeyCeremony(
		t,
		first.request(t, owner, "POST", "/api/v1/auth/bootstrap/begin", map[string]any{}, 200),
	)

	first.request(
		t,
		owner,
		"POST",
		"/api/v1/auth/bootstrap/finish",
		map[string]any{
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(ownerKey.Registration(t, ceremony.Options)),
		},
		200,
	)
	// A migration cookie has no network authority and owner setup invalidates it.
	first.request(t, owner, "GET", "/api/v1/admin/devices", nil, 401)
	migration := first.client(t)

	migration.Jar = journeyCopyJar(t, owner.Jar)

	first.request(
		t,
		owner,
		"POST",
		"/api/v1/auth/owner/password",
		map[string]any{"email": "owner@example.test", "password": journeyPassword},
		204,
	)
	first.request(
		t,
		migration,
		"POST",
		"/api/v1/auth/owner/password",
		map[string]any{"email": "owner@example.test", "password": journeyPassword},
		401,
	)
	journeyPasskeyLogin(t, first, owner, "owner@example.test", journeyPassword, ownerKey)
	first.request(t, owner, "GET", "/admin/security", nil, 200)
	first.request(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/email/verification",
		map[string]any{},
		204,
	)
	verification := journeyMailToken(
		t,
		pool,
		mail.worker,
		identity.OwnerAccountID,
		notifications.EmailVerification,
		"owner@example.test",
	)

	first.request(
		t,
		owner,
		"POST",
		"/api/v1/auth/email/verify",
		map[string]any{"token": verification},
		204,
	)
	first.request(
		t,
		owner,
		"POST",
		"/api/v1/auth/email/verify",
		map[string]any{"token": verification},
		401,
	)

	account, err := identitypg.New(pool).Account(t.Context(), identity.OwnerAccountID)

	if err != nil || account.EmailVerifiedAt == nil ||
		string(account.UserHandle) != "homeharbor-admin-v1" {
		t.Fatal("owner confirmation changed legacy identity", err)
	}

	first.request(t, owner, "POST", "/api/v1/admin/account/mail/test", map[string]any{}, 202)

	found, err := mail.worker.DispatchOnce(t.Context())

	if err != nil || !found {
		t.Fatal("owner SMTP test was not dispatched", err)
	}

	var smtpStatus struct {
		Configured bool
		Test       notifications.TestStatus
	}

	if json.Unmarshal(
		first.request(t, owner, "GET", "/api/v1/admin/account/mail/status", nil, 200),
		&smtpStatus,
	) != nil ||
		!smtpStatus.Configured ||
		smtpStatus.Test.State != "sent" {
		t.Fatal("SMTP acceptance not reflected in owner status")
	}

	// No Origin or CSRF bypass is hidden by directly invoking AccountHandler.
	request := first.newRequest(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/sessions/revoke-all",
		map[string]any{},
	)
	request.Header.Set("Origin", "https://foreign.example")
	first.send(t, owner, request, 401)
	request = first.newRequest(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/sessions/revoke-all",
		map[string]any{},
	)

	request.Header.Del(websession.CSRFHeaderName)
	first.send(t, owner, request, 401)
	first.request(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/admins/invite",
		map[string]any{"email": "invited@example.test"},
		201,
	)

	invited, err := identitypg.New(pool).AccountByEmail(t.Context(), "invited@example.test")
	if err != nil {
		t.Fatal(err)
	}

	invitation := journeyMailToken(
		t,
		pool,
		mail.worker,
		invited.ID,
		notifications.AdminInvitation,
		invited.Email,
	)

	member := first.client(t)

	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/invitation/accept",
		map[string]any{"token": invitation, "email": invited.Email, "password": journeyPassword},
		200,
	)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": invited.Email, "password": journeyPassword},
		401,
	)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/enrollment/password",
		map[string]any{"email": invited.Email, "password": journeyPassword},
		200,
	)
	// The invited setup proof never authorizes the network.
	first.request(t, member, "GET", "/api/v1/admin/devices", nil, 401)
	memberKey := authenticator.New(t, "example.com", journeyOrigin)

	ceremony = journeyCeremony(
		t,
		first.request(
			t,
			member,
			"POST",
			"/api/v1/auth/enrollment/passkey/begin",
			map[string]any{"name": "Fixture laptop"},
			200,
		),
	)

	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/enrollment/passkey/finish",
		map[string]any{
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(memberKey.Registration(t, ceremony.Options)),
		},
		204,
	)
	first.request(t, member, "GET", "/api/v1/admin/devices", nil, 401)
	journeyPasskeyLogin(t, first, member, invited.Email, journeyPassword, memberKey)
	first.request(t, member, "GET", "/api/v1/admin/devices", nil, 200)
	first.request(t, member, "GET", "/admin/administrators", nil, 403)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/admin/account/admins/invite",
		map[string]any{"email": "escalated@example.test"},
		403,
	)
	// Add TOTP through the same runtime and retain both factors across reset.
	var totp identity.TOTPEnrollment

	if json.Unmarshal(
		first.request(t, member, "POST", "/api/v1/admin/account/totp/begin", map[string]any{}, 200),
		&totp,
	) != nil ||
		totp.Secret == "" {
		t.Fatal("TOTP enrollment missing")
	}

	first.request(
		t,
		member,
		"POST",
		"/api/v1/admin/account/totp/confirm",
		map[string]any{"code": journeyTOTP(t, totp.Secret, time.Now())},
		204,
	)
	// Use the explicitly accepted next TOTP step so enrollment's consumed step
	// is not replayed and the contract needs no real-time30s delay.
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": invited.Email, "password": journeyPassword},
		200,
	)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/factor",
		map[string]any{
			"method": "totp",
			"code":   journeyTOTP(t, totp.Secret, time.Now().Add(30*time.Second)),
		},
		204,
	)
	security := first.request(t, member, "GET", "/admin/security", nil, 200)

	if !strings.Contains(html.UnescapeString(string(security)), "Password + authenticator") {
		t.Fatal("TOTP session did not reach account UI")
	}

	beforeReset := first.client(t)

	beforeReset.Jar = journeyCopyJar(t, member.Jar)

	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password/reset/request",
		map[string]any{"email": invited.Email},
		202,
	)
	reset := journeyMailToken(
		t,
		pool,
		mail.worker,
		invited.ID,
		notifications.PasswordReset,
		invited.Email,
	)
	replacement := "replacement fixture password"

	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password/reset/finish",
		map[string]any{"token": reset, "password": replacement},
		204,
	)
	second.request(t, beforeReset, "GET", "/api/v1/admin/devices", nil, 401)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": invited.Email, "password": journeyPassword},
		401,
	)
	journeyPasskeyLogin(t, first, member, invited.Email, replacement, memberKey)

	updated, err := identitypg.New(pool).Account(t.Context(), invited.ID)
	if err != nil {
		t.Fatal(err)
	}

	state, err := identitypg.New(pool).
		FactorState(t.Context(), identity.AccountScope{AccountID: updated.ID, AuthVersion: updated.AuthVersion, Purpose: identity.SessionAdmin})

	if err != nil || !state.TOTP || len(state.Passkeys) != 1 {
		t.Fatal("reset removed verification factors", err)
	}

	// Explicit all-session revocation is live on the other composition immediately.
	oldOwner := first.client(t)

	oldOwner.Jar = journeyCopyJar(t, owner.Jar)

	first.request(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/sessions/revoke-all",
		map[string]any{},
		204,
	)
	second.request(t, oldOwner, "GET", "/api/v1/admin/devices", nil, 401)
	first.request(t, member, "GET", "/api/v1/admin/devices", nil, 200)
	journeyPasskeyLogin(t, first, owner, "owner@example.test", journeyPassword, ownerKey)
	first.request(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/admins/"+identity.OwnerAccountID+"/revoke",
		map[string]any{},
		401,
	)
	first.request(
		t,
		owner,
		"POST",
		"/api/v1/admin/account/admins/"+invited.ID+"/revoke",
		map[string]any{},
		204,
	)
	second.request(t, member, "GET", "/api/v1/admin/devices", nil, 401)
	first.request(
		t,
		member,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": invited.Email, "password": replacement},
		401,
	)
	// A failure of either replica-owned connection cannot become an empty success.
	secondPool.Close()
	second.request(t, owner, "GET", "/api/v1/admin/devices", nil, 503)

	if err := secondStores.redis.Close(); err != nil {
		t.Fatal(err)
	}

	second.request(
		t,
		owner,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": "owner@example.test", "password": journeyPassword},
		503,
	)
	first.request(t, owner, "GET", "/api/v1/admin/devices", nil, 200)
	first.request(t, owner, "POST", "/api/v1/auth/logout", map[string]any{}, 204)
	first.request(t, owner, "GET", "/api/v1/admin/devices", nil, 401)
}

type accountJourneyServer struct{ server *httptest.Server }

func accountJourneyConfig(t *testing.T) config.Control {
	t.Helper()

	password, err := os.ReadFile(os.Getenv("TEST_MAILPIT_PASSWORD_FILE"))
	if err != nil {
		t.Fatal("capture credential unavailable")
	}
	defer clear(password)

	port, err := strconv.Atoi(os.Getenv("TEST_MAILPIT_STARTTLS_PORT"))
	if err != nil {
		t.Fatal("capture port unavailable")
	}

	cfg := config.Control{Runtime: config.DefaultRuntime(false)}
	// Multiple independent account journeys share one real loopback IP. Separate
	// quota contracts keep the deployed default5/min password/proof buckets pinned.
	cfg.Runtime.AuthPerMinute = 30
	cfg.Runtime.APIPerMinute = 600
	cfg.Networking.NetworkID = "test-accounts-" + uuid.NewString()
	cfg.Auth = config.Auth{
		RPID:                  "example.com",
		RPOrigin:              journeyOrigin,
		SessionSigningKey:     strings.Repeat("s", 32),
		CeremonyEncryptionKey: strings.Repeat("c", 32),
		SessionTTL:            "1h",
		CeremonyTTL:           "5m",
	}
	cfg.Relay = config.Relay{
		PublicURL: "wss://relay.example.test/relay/udp",
		TicketKey: strings.Repeat("r", 32),
		TicketTTL: "1m",
	}
	cfg.SMTP = config.SMTP{
		Enabled:  true,
		Host:     "localhost",
		Port:     port,
		Username: "homeharbor",
		Password: strings.TrimSpace(string(password)),
		From:     "homeharbor@example.test",
		Mode:     "starttls",
		Timeout:  5 * time.Second,
		CAFile:   os.Getenv("TEST_MAILPIT_CA_FILE"),
	}

	return cfg
}

func journeyRedis(t *testing.T) *redisclient.Client {
	t.Helper()

	options, err := redisclient.ParseURL(os.Getenv("TEST_REDIS_URL"))
	if err != nil {
		t.Fatal("test Redis unavailable")
	}

	options.ContextTimeoutEnabled = true
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	client := redisclient.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func journeyServer(
	t *testing.T,
	cfg config.Control,
	stores *runtimeStores,
	mail *notificationRuntime,
	logger *slog.Logger,
) accountJourneyServer {
	t.Helper()

	app, _, _, err := buildHTTP(cfg, logger, stores, mail)
	if err != nil {
		t.Fatal("HTTP composition failed", err)
	}

	server := httptest.NewTLSServer(app.Handler())
	t.Cleanup(server.Close)
	return accountJourneyServer{server: server}
}

func (s accountJourneyServer) client(t *testing.T) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()

	roots.AddCert(s.server.Certificate())
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "example.com:443" {
				return nil, fmt.Errorf("unexpected account fixture destination")
			}

			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(
				ctx,
				network,
				s.server.Listener.Addr().String(),
			)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{
		Transport:     transport,
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func journeyCopyJar(t *testing.T, source http.CookieJar) http.CookieJar {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	origin, _ := url.Parse(journeyOrigin)

	jar.SetCookies(origin, source.Cookies(origin))
	return jar
}

func (s accountJourneyServer) newRequest(
	t *testing.T,
	client *http.Client,
	method, path string,
	body any,
) *http.Request {
	t.Helper()
	var input io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}

		input = strings.NewReader(string(payload))
	}

	request, err := http.NewRequestWithContext(t.Context(), method, journeyOrigin+path, input)
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", journeyOrigin)
	origin, _ := url.Parse(journeyOrigin)
	for _, cookie := range client.Jar.Cookies(origin) {
		if cookie.Name == websession.CSRFCookieName {
			request.Header.Set(websession.CSRFHeaderName, cookie.Value)
		}
	}

	return request
}

func (s accountJourneyServer) request(
	t *testing.T,
	client *http.Client,
	method, path string,
	body any,
	want int,
) []byte {
	t.Helper()
	return s.send(t, client, s.newRequest(t, client, method, path, body), want)
}

func (s accountJourneyServer) send(
	t *testing.T,
	client *http.Client,
	request *http.Request,
	want int,
) []byte {
	t.Helper()
	// Preserve the caller's cookies while addressing this particular replica.
	replica := *client

	target := s.client(t)
	replica.Transport = target.Transport

	response, err := replica.Do(request)
	if err != nil {
		t.Fatal("verified account HTTP request failed", err)
	}
	defer func() { _ = response.Body.Close() }()

	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal("account response unavailable")
	}

	if response.StatusCode != want {
		t.Fatalf(
			"%s %s status%d want%d",
			request.Method,
			request.URL.Path,
			response.StatusCode,
			want,
		)
	}
	if strings.HasPrefix(request.URL.Path, "/api/") &&
		response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("account response may be cached")
	}

	return payload
}

func journeyCeremony(t *testing.T, payload []byte) identity.BeginCeremony {
	t.Helper()
	var value identity.BeginCeremony

	if json.Unmarshal(payload, &value) != nil || value.CeremonyID == "" {
		t.Fatal("ceremony unavailable")
	}

	return value
}

func journeyPasskeyLogin(
	t *testing.T,
	s accountJourneyServer,
	client *http.Client,
	email, password string,
	key *authenticator.Authenticator,
) {
	t.Helper()
	s.request(
		t,
		client,
		"POST",
		"/api/v1/auth/password",
		map[string]any{"email": email, "password": password},
		200,
	)
	ceremony := journeyCeremony(
		t,
		s.request(t, client, "POST", "/api/v1/auth/passkey/begin", map[string]any{}, 200),
	)

	s.request(
		t,
		client,
		"POST",
		"/api/v1/auth/factor",
		map[string]any{
			"method":      "passkey",
			"ceremony_id": ceremony.CeremonyID,
			"response":    json.RawMessage(key.Assertion(t, ceremony.Options)),
		},
		204,
	)
}

func journeyTOTP(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal("invalid TOTP setup")
	}
	defer clear(key)

	var counter [8]byte

	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)

	_, _ = mac.Write(counter[:])

	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15

	return fmt.Sprintf(
		"%06d",
		(binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000,
	)
}

func journeyMailToken(
	t *testing.T,
	pool *pgxpool.Pool,
	worker *notifications.Worker,
	account string,
	kind notifications.Kind,
	recipient string,
) string {
	t.Helper()
	var id string

	if err := pool.QueryRow(t.Context(), `SELECT id FROM notification_deliveries WHERE account_id=$1 AND kind=$2 AND status='pending' ORDER BY created_at DESC LIMIT 1`, account, kind).
		Scan(&id); err != nil {
		t.Fatal("expected sealed account mail missing", err)
	}

	endpoint, err := url.Parse(os.Getenv("TEST_MAILPIT_STARTTLS_URL"))

	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" ||
		endpoint.User != nil {
		t.Fatal("capture must be owned loopback")
	}

	endpoint.Path = "/api/v1/message/latest/raw"
	client := &http.Client{
		Timeout:       3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for range 30 {
		found, err := worker.DispatchOnce(t.Context())

		if err != nil || !found {
			t.Fatal("real account mail worker did not submit expected message", err)
		}

		request, err := http.NewRequestWithContext(t.Context(), "GET", endpoint.String(), nil)
		if err != nil {
			t.Fatal("capture request unavailable")
		}

		response, err := client.Do(request)
		if err != nil {
			t.Fatal("capture API unavailable")
		}

		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 128<<10))

		_ = response.Body.Close()

		if readErr != nil || response.StatusCode != 200 {
			t.Fatal("captured account MIME unavailable")
		}

		message, err := netmail.ReadMessage(bufio.NewReader(strings.NewReader(string(raw))))
		clear(raw)
		if err != nil {
			t.Fatal("invalid captured account MIME")
		}

		if message.Header.Get("Message-Id") != "<"+id+"@example.test>" {
			continue
		}

		addresses, err := message.Header.AddressList("To")

		if err != nil || len(addresses) != 1 || addresses[0].Address != recipient {
			t.Fatal("account email reached wrong recipient")
		}

		text, err := io.ReadAll(quotedprintable.NewReader(message.Body))
		if err != nil {
			t.Fatal("account link MIME unavailable")
		}
		defer clear(text)

		for _, word := range strings.Fields(string(text)) {
			link, err := url.Parse(word)
			if err != nil || link.Scheme != "https" || link.Host != "example.com" {
				continue
			}

			proof, err := url.ParseQuery(link.Fragment)
			if err == nil && len(proof.Get("token")) == 43 {
				return proof.Get("token")
			}
		}

		t.Fatal("captured account mail omitted single-use link")
	}

	t.Fatal("expected account mail not captured within bounded dispatches")

	return ""
}
