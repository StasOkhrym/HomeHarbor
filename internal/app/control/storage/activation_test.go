package storage_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	workflowpg "github.com/sokhrym/go-tunnels/internal/app/control/storage"
	"github.com/sokhrym/go-tunnels/internal/app/control/workflows"
	devicepg "github.com/sokhrym/go-tunnels/internal/control/devices/storage"
	"github.com/sokhrym/go-tunnels/internal/control/httpapi"
	"github.com/sokhrym/go-tunnels/internal/control/invites"
	invitepg "github.com/sokhrym/go-tunnels/internal/control/invites/storage"
	"github.com/sokhrym/go-tunnels/internal/invite"
	"github.com/sokhrym/go-tunnels/internal/node"
	"github.com/sokhrym/go-tunnels/internal/platform/redissecurity"
	"github.com/sokhrym/go-tunnels/internal/snapshot"
	"github.com/sokhrym/go-tunnels/internal/tunnel"
	"github.com/sokhrym/go-tunnels/migrations"
)

type snapshotReader struct{ envelope snapshot.Envelope }

func (s *snapshotReader) Latest(context.Context) (snapshot.Envelope, error) { return s.envelope, nil }

type fixture struct {
	pool       *pgxpool.Pool
	activation *workflows.Activation
	devices    *devicepg.Repository
	root       ed25519.PrivateKey
	deviceKey  ed25519.PrivateKey
	approval   invite.SignedApproval
	record     invites.Record
	snapshot   *snapshotReader
	wgKey      wgtypes.Key
	link       string
	code       string
}

func database(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(admin.Close)
	schema := fmt.Sprintf("activation_%d", time.Now().UnixNano())

	if _, err = admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Error(err)
		}
	})

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}

	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	if err = migrations.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}

	return pool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pool := database(t)
	ctx := context.Background()
	now := time.Now().UTC()
	root, rootKey, _ := ed25519.GenerateKey(rand.Reader)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO access_profiles(id,name,created_at) VALUES('family','Family',$1)`,
		now,
	); err != nil {
		t.Fatal(err)
	}
	local, err := invite.New("home", "family", time.Hour, now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := invite.SignPermit(local.Permit, rootKey, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	wgKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	publicWG := wgKey.PublicKey()
	proof, err := local.Proof("linux", deviceKey, local.Code, publicWG[:])
	if err != nil {
		t.Fatal(err)
	}
	repo := invitepg.New(pool)
	service := invites.NewService(repo, root, "home", time.Now)
	if err = service.SubmitProof(ctx, permit, proof); err != nil {
		t.Fatal(err)
	}
	r, err := repo.Get(ctx, proof.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := invite.SignApproval(
		invite.Approval{
			Version:            1,
			InviteID:           r.InviteID,
			ProfileID:          r.ProfileID,
			DeviceID:           r.DeviceID,
			DevicePublicKey:    r.DevicePublic,
			WireGuardPublicKey: r.WireGuardPublicKey,
		},
		rootKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	snap := &snapshotReader{}
	f := &fixture{
		pool:      pool,
		devices:   devicepg.New(pool, workflowpg.AppendEvent),
		root:      rootKey,
		deviceKey: deviceKey,
		approval:  approval,
		record:    r,
		snapshot:  snap,
	}
	f.wgKey = wgKey
	f.code = local.Code
	f.link, err = local.Link("https://control.example", permit)
	if err != nil {
		t.Fatal(err)
	}
	var security workflows.ChallengeRepository
	if redisURL := os.Getenv("TEST_REDIS_URL"); redisURL != "" {
		options, err := redis.ParseURL(redisURL)
		if err != nil {
			t.Fatal(err)
		}
		client := redis.NewClient(options)
		t.Cleanup(func() { _ = client.Close() })
		if err := client.Ping(ctx).Err(); err != nil {
			t.Fatal(err)
		}
		security = redissecurity.New(client, fmt.Sprintf("activation-envtest-%d", time.Now().UnixNano()))
	}
	f.activation = workflows.NewActivation(
		workflowpg.NewActivationUnitOfWork(pool),
		repo,
		snap,
		security,
		root,
		"home",
		time.Now,
		rand.Reader,
	)
	return f
}

func (f *fixture) publish(t *testing.T) {
	t.Helper()
	var err error
	f.snapshot.envelope, err = snapshot.Sign(
		snapshot.NetworkSnapshot{
			NetworkID: "home",
			Revision:  1,
			Devices: []snapshot.Device{
				{
					ID:                 "linux",
					Role:               "client",
					IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(f.record.DevicePublic),
					WireGuardPublicKey: base64.StdEncoding.EncodeToString(f.record.WireGuardPublicKey),
				},
			},
			Profiles: []snapshot.AccessProfile{{ID: "family", Name: "Family", DeviceIDs: []string{"linux"}}},
		},
		f.root,
		"root-1",
	)
	if err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) claim(t *testing.T) workflows.ClaimResult {
	t.Helper()
	ctx := context.Background()
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := workflows.SignClaim(c, f.deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.activation.Claim(ctx, f.record.InviteID, p)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPostgresApprovalRetriesExactDiffWithoutCredentialAndWritesOneOutboxPair(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for range 2 {
		result, err := f.activation.ApproveSigned(ctx, f.approval)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := json.Marshal(result)
		if strings.Contains(string(data), "credential") || result.Status != invites.StatusApproved {
			t.Fatalf("unsafe result %s", data)
		}
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM event_outbox`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("events=%d err=%v", count, err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM device_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("approval issued credentials=%d err=%v", count, err)
	}
	d, err := f.devices.Device(ctx, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if d.WireGuardPublicKey != base64.StdEncoding.EncodeToString(f.record.WireGuardPublicKey) {
		t.Fatalf("WG encoding=%s", d.WireGuardPublicKey)
	}
	bad, err := invite.SignApproval(
		invite.Approval{
			Version:            1,
			InviteID:           f.record.InviteID,
			ProfileID:          "other",
			DeviceID:           "linux",
			DevicePublicKey:    f.record.DevicePublic,
			WireGuardPublicKey: f.record.WireGuardPublicKey,
		},
		f.root,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.activation.ApproveSigned(ctx, bad); err == nil {
		t.Fatal("mismatched approved retry accepted")
	}
}

func TestPostgresApprovalRollsBackAllTablesAtEveryFailureBoundary(t *testing.T) {
	for _, table := range []string{"devices", "access_profile_devices", "invite_records", "event_outbox"} {
		t.Run(table, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			if _, err := f.pool.Exec(
				ctx,
				`CREATE FUNCTION reject_activation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected activation failure'; END $$; CREATE TRIGGER reject_activation BEFORE INSERT OR UPDATE ON `+table+` FOR EACH ROW EXECUTE FUNCTION reject_activation()`,
			); err != nil {
				t.Fatal(err)
			}
			if _, err := f.activation.ApproveSigned(ctx, f.approval); err == nil {
				t.Fatal("failure accepted")
			}
			for _, empty := range []string{"devices", "device_credentials", "access_profile_devices", "event_outbox"} {
				var n int
				if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM `+empty).Scan(&n); err != nil || n != 0 {
					t.Fatalf("%s rows=%d err=%v", empty, n, err)
				}
			}
			var status string
			if err := f.pool.QueryRow(ctx, `SELECT status FROM invite_records WHERE invite_id=$1`, f.record.InviteID).
				Scan(&status); err != nil ||
				status != "pending" {
				t.Fatalf("status=%s err=%v", status, err)
			}
		})
	}
}

func TestPostgresClaimsRetryReplaceCredentialReplayAndConcurrentCredentials(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	first := f.claim(t)
	second := f.claim(t)
	if first.Device.Credential == second.Device.Credential {
		t.Fatal("credential reused")
	}
	if _, err := f.devices.AuthenticateCredential(
		ctx,
		sha256.Sum256([]byte(first.Device.Credential)),
		time.Now(),
	); err == nil {
		t.Fatal("old credential remains active")
	}
	if _, err := f.devices.AuthenticateCredential(
		ctx,
		sha256.Sum256([]byte(second.Device.Credential)),
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := workflows.SignClaim(c, f.deviceKey)
	if _, err = f.activation.Claim(ctx, f.record.InviteID, proof); err != nil {
		t.Fatal(err)
	}
	if _, err = f.activation.Claim(ctx, f.record.InviteID, proof); err == nil {
		t.Fatal("claim replay accepted")
	}
	var wg sync.WaitGroup
	results := make(chan workflows.ClaimResult, 8)
	failures := make(chan error, 8)
	for range 8 {
		c, err := f.activation.Challenge(ctx, f.record.InviteID)
		if err != nil {
			t.Fatal(err)
		}
		proof, _ := workflows.SignClaim(c, f.deviceKey)
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := f.activation.Claim(ctx, f.record.InviteID, proof)
			if err != nil {
				failures <- err
			} else {
				results <- result
			}
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	active := 0
	for r := range results {
		if _, err := f.devices.AuthenticateCredential(
			ctx,
			sha256.Sum256([]byte(r.Device.Credential)),
			time.Now(),
		); err == nil {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active concurrent credentials=%d", active)
	}
	if err := f.devices.RevokeDevice(ctx, "linux", time.Now()); err != nil {
		t.Fatal(err)
	}
	c, err = f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ = workflows.SignClaim(c, f.deviceKey)
	if _, err = f.activation.Claim(ctx, f.record.InviteID, proof); err == nil {
		t.Fatal("revoked device claimed")
	}
}

func TestPostgresClaimOutboxFailureRollsBackCredentialReplacement(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	first := f.claim(t)
	if _, err := f.pool.Exec(
		ctx,
		`CREATE FUNCTION reject_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'outbox unavailable'; END $$; CREATE TRIGGER reject_claim BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION reject_claim()`,
	); err != nil {
		t.Fatal(err)
	}
	c, err := f.activation.Challenge(ctx, f.record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := workflows.SignClaim(c, f.deviceKey)
	if _, err = f.activation.Claim(ctx, f.record.InviteID, proof); err == nil {
		t.Fatal("outbox failure ignored")
	}
	if _, err := f.devices.AuthenticateCredential(
		ctx,
		sha256.Sum256([]byte(first.Device.Credential)),
		time.Now(),
	); err != nil {
		t.Fatal("previous credential lost after rollback:", err)
	}
}

type lostClaimResponse struct {
	transport http.RoundTripper
	lost      bool
}

func (l *lostClaimResponse) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := l.transport.RoundTrip(r)
	if err == nil && !l.lost && strings.HasSuffix(r.URL.Path, "/claim") && response.StatusCode == http.StatusOK {
		l.lost = true
		_ = response.Body.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return response, err
}

func TestPostgresHTTPResponseLossRequestsFreshChallengeAndPersistsReplacement(t *testing.T) {
	if os.Getenv("TEST_REDIS_URL") == "" {
		t.Skip("TEST_REDIS_URL is not set")
	}
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := f.activation.ApproveSigned(ctx, f.approval); err != nil {
		t.Fatal(err)
	}
	f.publish(t)
	records := invites.NewService(
		invitepg.New(f.pool),
		f.root.Public().(ed25519.PublicKey),
		"home",
		time.Now,
		invites.WithApprovalWorkflow(f.activation),
	)
	mux := http.NewServeMux()
	handler := httpapi.NewActivationHandler(f.activation, f.activation)
	mux.HandleFunc("POST /api/v1/invites/{id}/challenge", handler.Challenge)
	mux.HandleFunc("POST /api/v1/invites/{id}/claim", handler.Claim)
	mux.HandleFunc("POST /api/v1/invites/proof", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Permit invite.SignedPermit `json:"permit"`
			Proof  invite.Proof        `json:"proof"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := records.SubmitProof(r.Context(), input.Permit, input.Proof); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(202)
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	transport := &lostClaimResponse{transport: server.Client().Transport}
	client := &http.Client{Transport: transport}
	state := node.State{
		IdentityPrivateKey: base64.RawURLEncoding.EncodeToString(f.deviceKey),
		IdentityPublicKey:  base64.RawURLEncoding.EncodeToString(f.record.DevicePublic),
		WireGuard:          tunnel.Identity{PrivateKey: f.wgKey.String(), PublicKey: f.wgKey.PublicKey().String()},
	}
	path := filepath.Join(t.TempDir(), "linux.json")
	err := node.EnrollByInvite(
		ctx,
		client,
		node.InviteEnrollment{
			ControlURL:    server.URL,
			InviteLink:    f.link,
			Code:          f.code,
			DeviceID:      "linux",
			StatePath:     path,
			RootPublicKey: f.root.Public().(ed25519.PublicKey),
			NetworkID:     "home",
			PollInterval:  time.Millisecond,
		},
		&state,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !transport.lost {
		t.Fatal("test did not lose a committed response")
	}
	loaded, err := node.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.devices.AuthenticateCredential(
		ctx,
		sha256.Sum256([]byte(loaded.DeviceCredential)),
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	var total, active int
	if err := f.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE revoked_at IS NULL) FROM device_credentials`).
		Scan(&total, &active); err != nil ||
		total != 2 ||
		active != 1 {
		t.Fatalf("credentials total=%d active=%d err=%v", total, active, err)
	}
	d, err := f.devices.Device(ctx, "linux")
	if err != nil || d.Credential != "" {
		t.Fatal("plaintext credential was persisted")
	}
}
