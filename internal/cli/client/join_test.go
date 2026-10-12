package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/invite"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
)

func TestJoinIsSeparateFromNormalClientRunAndNeverAcceptsSecretsAsFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	command := NewCommand()

	code := host.Execute(
		context.Background(),
		[]string{"join", "--help"},
		&stdout,
		&stderr,
		command,
	)

	if code != 0 {
		t.Fatalf("join help status=%d stderr=%s", code, stderr.String())
	}

	help := stdout.String()
	for _, expected := range []string{"--control", "--ca-file", "--root-public-key", "--network-id", "--state"} {
		if !strings.Contains(help, expected) {
			t.Fatalf("join help lacks %s", expected)
		}
	}

	for _, forbidden := range []string{"--invite", "--code", "--token", "--insecure"} {
		if strings.Contains(help, forbidden) {
			t.Fatalf("join advertises private or unsafe flag %s", forbidden)
		}
	}
}

type joinFixture struct {
	server   *httptest.Server
	root     ed25519.PublicKey
	signing  ed25519.PrivateKey
	caPath   string
	rootPath string
	state    string
}

func newJoinFixture(t *testing.T, handler http.Handler) joinFixture {
	t.Helper()

	root, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.pem")

	certificate := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw},
	)

	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	rootPath := filepath.Join(directory, "root.pub")

	if err := os.WriteFile(
		rootPath,
		[]byte(base64.RawURLEncoding.EncodeToString(root)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	return joinFixture{
		server: server, root: root, signing: signing, caPath: caPath,
		rootPath: rootPath, state: filepath.Join(directory, "client.json"),
	}
}

func (f joinFixture) link(t *testing.T, network string, at time.Time) (string, string) {
	t.Helper()

	local, err := invite.New(network, "family", time.Hour, at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	permit, err := invite.SignPermit(local.Permit, f.signing, "root-1")
	if err != nil {
		t.Fatal(err)
	}

	link, err := local.Link(f.server.URL, permit)
	if err != nil {
		t.Fatal(err)
	}

	return link, local.Code
}

func (f joinFixture) execute(
	ctx context.Context,
	network, link, code string,
) (int, string, string) {
	command := NewCommand()

	command.SetIn(strings.NewReader(link + "\n" + code + "\n"))
	var stdout, stderr bytes.Buffer

	exit := host.Execute(ctx, []string{
		"join", "--control", f.server.URL, "--ca-file", f.caPath,
		"--root-public-key", f.rootPath, "--network-id", network,
		"--trust-fingerprint", trustFingerprint(f.root, network), "--state", f.state,
	}, &stdout, &stderr, command)

	return exit, stdout.String(), stderr.String()
}

func TestJoinRejectsWrongRootOrNetwork(t *testing.T) {
	calls := 0

	fixture := newJoinFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))

	link, code := fixture.link(t, "home", time.Now())

	otherRoot, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(
		fixture.rootPath, []byte(base64.RawURLEncoding.EncodeToString(otherRoot)), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	if exit, _, _ := fixture.execute(context.Background(), "home", link, code); exit == 0 {
		t.Fatal("join accepted a permit signed by another root")
	}

	if err := os.WriteFile(
		fixture.rootPath, []byte(base64.RawURLEncoding.EncodeToString(fixture.root)), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	if exit, _, _ := fixture.execute(context.Background(), "other", link, code); exit == 0 {
		t.Fatal("join accepted a permit for another network")
	}

	if calls != 0 {
		t.Fatalf("invalid trust caused %d HTTP requests", calls)
	}
}

func TestInvalidOrExpiredInviteLeavesUnenrolled(t *testing.T) {
	calls := 0
	fixture := newJoinFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	expiredLink, expiredCode := fixture.link(t, "home", time.Now().Add(-2*time.Hour))
	validLink, validCode := fixture.link(t, "home", time.Now())
	for _, candidate := range []struct{ link, code string }{
		{expiredLink, expiredCode},
		{validLink + "&unexpected=1", validCode},
	} {
		exit, _, _ := fixture.execute(context.Background(), "home", candidate.link, candidate.code)
		if exit == 0 || calls != 0 {
			t.Fatalf("invalid invite accepted or transmitted: exit=%d calls=%d", exit, calls)
		}
		state, err := node.Load(fixture.state)
		if err != nil || state.DeviceCredential != "" || state.DeviceID != "" {
			t.Fatalf("invalid invite enrolled a client: device=%q credential_present=%t err=%v",
				state.DeviceID, state.DeviceCredential != "", err)
		}
	}
}

func TestPendingDoesNotApplyTunnelAndPrivateInputNotPrinted(t *testing.T) {
	proofs, claims := 0, 0
	lockDenied := false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var fixture joinFixture
	fixture = newJoinFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/invites/proof":
			proofs++
			other, err := localstate.Open(fixture.state)
			lockDenied = err != nil
			if err == nil {
				_ = other.Close()
			}
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/challenge"):
			cancel()
			w.WriteHeader(http.StatusConflict)
		case strings.HasSuffix(r.URL.Path, "/claim"):
			claims++
			w.WriteHeader(http.StatusConflict)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	link, code := fixture.link(t, "home", time.Now())
	exit, stdout, stderr := fixture.execute(ctx, "home", link, code)
	if exit == 0 || proofs != 1 || claims != 0 || !lockDenied ||
		!strings.Contains(stdout, "Pending") ||
		strings.Contains(stdout, "applied") ||
		strings.Contains(stdout+stderr, link) ||
		strings.Contains(stdout+stderr, code) {
		t.Fatalf(
			"unsafe pending state: exit=%d proofs=%d claims=%d lock_denied=%t stdout=%q stderr=%q",
			exit,
			proofs,
			claims,
			lockDenied,
			stdout,
			stderr,
		)
	}
	state, err := node.Load(fixture.state)
	if err != nil || state.DeviceCredential != "" || state.DeviceID != "" {
		t.Fatalf("pending client has credential: device=%q credential_present=%t err=%v",
			state.DeviceID, state.DeviceCredential != "", err)
	}
}

func TestJoinClaimsOnlyTheGeneratedClientIdentity(t *testing.T) {
	var submitted invite.Proof
	claimCount := 0
	fixture := newJoinFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/invites/proof":
			var input struct {
				Proof invite.Proof `json:"proof"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			submitted = input.Proof
			w.WriteHeader(http.StatusAccepted)
		case strings.HasSuffix(r.URL.Path, "/challenge"):
			_ = json.NewEncoder(w).Encode(protocol.ClaimChallenge{
				Version: 1, NetworkID: "home", InviteID: submitted.InviteID,
				DeviceID:  submitted.DeviceID,
				Nonce:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				ExpiresAt: time.Now().Add(time.Minute).Unix(),
			})
		case strings.HasSuffix(r.URL.Path, "/claim"):
			claimCount++
			var proof protocol.ClaimProof
			if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
				t.Error(err)
			}
			if proof.Challenge.DeviceID != submitted.DeviceID {
				t.Error("claim changed the device ID")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"device": map[string]any{
				"id":     submitted.DeviceID,
				"role":   "client",
				"status": "active",
				"identity_public_key": base64.RawURLEncoding.EncodeToString(
					submitted.DevicePublicKey,
				),
				"wireguard_public_key": base64.StdEncoding.EncodeToString(
					submitted.WireGuardPublicKey,
				),
				"credential":            base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				"credential_expires_at": time.Now().Add(15 * time.Minute),
			}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	link, code := fixture.link(t, "home", time.Now())
	exit, stdout, stderr := fixture.execute(context.Background(), "home", link, code)
	if exit != 0 || claimCount != 1 || !strings.Contains(stdout, "Pending") ||
		!strings.Contains(stdout, "Approved") || !strings.Contains(stdout, "Credential claimed") ||
		strings.Contains(stdout+stderr, link) || strings.Contains(stdout+stderr, code) {
		t.Fatalf("join status=%d claims=%d stdout=%q stderr=%q", exit, claimCount, stdout, stderr)
	}
	state, err := node.Load(fixture.state)
	if err != nil || state.DeviceID != submitted.DeviceID || state.DeviceCredential == "" {
		t.Fatalf("claim was not persisted: device=%q credential_present=%t err=%v",
			state.DeviceID, state.DeviceCredential != "", err)
	}
	exit, _, _ = fixture.execute(context.Background(), "home", link, code)
	if exit == 0 || claimCount != 1 {
		t.Fatalf("joined client replayed claim: exit=%d claims=%d", exit, claimCount)
	}
}
