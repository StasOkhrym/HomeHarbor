package coordination

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/jackc/pgx/v5/pgxpool"

	workflowstorage "github.com/StasOkhrym/homeharbor/internal/app/control/storage"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	devicesstorage "github.com/StasOkhrym/homeharbor/internal/control/devices/storage"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/testutil"
)

// Real independent pools/services/handlers share only durable authority. An idle
// socket on B must observe A's committed revoke without a process-local hint.
func TestPostgresCoordinationCrossReplicaRevoke(t *testing.T) {
	poolA := testutil.Postgres(t)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	poolB, err := pgxpool.NewWithConfig(ctx, poolA.Config())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(poolB.Close)
	serviceA := devices.NewService(
		devicesstorage.New(poolA, workflowstorage.AppendEvent),
		time.Now,
		nil,
	)
	serviceB := devices.NewService(
		devicesstorage.New(poolB, workflowstorage.AppendEvent),
		time.Now,
		nil,
	)

	identity, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}

	token, err := serviceA.IssueEnrollmentToken(ctx, devices.RoleClient, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	device, err := serviceA.Enroll(
		ctx,
		devices.EnrollRequest{
			Token:              token.Token,
			Name:               "cross-replica",
			IdentityPublicKey:  identity.IdentityPublicKey,
			WireGuardPublicKey: identity.WireGuard.PublicKey,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	matched, err := serviceB.Authenticate(ctx, device.Credential)
	if err != nil {
		t.Fatal(err)
	}

	if matched.ID != device.ID || !matched.CredentialExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf(
			"B did not match a live durable credential: id=%s expiry=%s",
			matched.ID,
			matched.CredentialExpiresAt,
		)
	}
	if matched.CredentialExpiresAt.Sub(device.CredentialExpiresAt).Abs() > time.Microsecond {
		t.Fatal("B matched a different credential expiry")
	}

	t.Logf(
		"replica B matched durable credential expiry %s",
		matched.CredentialExpiresAt.Format(time.RFC3339Nano),
	)
	servers := make([]*httptest.Server, 0, 2)
	for _, svc := range []*devices.Service{serviceA, serviceB} {
		handler := NewHandler(svc, svc, coordinationSnapshotStub{}, nil, nil)
		server := httptest.NewServer(handler)
		ownerCtx, stop := context.WithCancel(ctx)
		joined := make(chan error, 1)
		go func() { joined <- handler.Run(ownerCtx) }()
		t.Cleanup(func() {
			stop()
			select {
			case err := <-joined:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(3 * time.Second):
				t.Error("coordination handlers did not join")
			}

			server.Close()
		})
		servers = append(servers, server)
	}

	connection := dialCredentialPeer(t, servers[1], device.ID, device.Credential)

	if err := serviceA.Revoke(ctx, device.ID); err != nil {
		t.Fatal(err)
	}

	// No messages, broadcasts, or local invalidation hints after this commit.
	// The five-second periodic SQL recheck must close this otherwise-idle socket.
	deadline, stop := context.WithTimeout(ctx, 7*time.Second)
	defer stop()

	var message any

	if err := wsjson.Read(deadline, connection, &message); err == nil || deadline.Err() != nil {
		t.Fatalf("idle B socket survived A revoke: read=%v context=%v", err, deadline.Err())
	}

	if !matched.CredentialExpiresAt.After(time.Now()) {
		t.Fatal("socket closed by natural expiry, not cross-replica revoke")
	}

	for _, server := range servers {
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer "+device.Credential)

		connection, response, err := websocket.Dial(
			ctx,
			"ws"+server.URL[4:],
			&websocket.DialOptions{HTTPHeader: headers},
		)
		if connection != nil {
			_ = connection.CloseNow()
		}

		if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked new admission accepted: response=%v error=%v", response, err)
		}
	}
}
