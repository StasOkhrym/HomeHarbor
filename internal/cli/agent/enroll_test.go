package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/StasOkhrym/homeharbor/internal/cli/host"
	"github.com/StasOkhrym/homeharbor/internal/control/devices"
	"github.com/StasOkhrym/homeharbor/internal/control/httpapi"
	"github.com/StasOkhrym/homeharbor/internal/control/identity"
	"github.com/StasOkhrym/homeharbor/internal/node"
	"github.com/StasOkhrym/homeharbor/internal/node/localstate"
	"github.com/StasOkhrym/homeharbor/internal/protocol"
	memorydevices "github.com/StasOkhrym/homeharbor/internal/testutil/control/devices"
	nodetest "github.com/StasOkhrym/homeharbor/internal/testutil/node"
)

type enrollFixture struct {
	server    *httptest.Server
	ca, state string
	token     string
	calls     atomic.Int32
}

func newEnrollFixture(t *testing.T, amend func(*protocol.EnrolledDevice)) *enrollFixture {
	t.Helper()
	f := &enrollFixture{token: "private-gateway-token"}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/enroll" {
			t.Error("finite enrollment attempted a runtime request")

			w.WriteHeader(http.StatusNotFound)
			return
		}

		var request protocol.EnrollmentRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)

			return
		}

		if request.Token != "private-gateway-token" || request.Name != "sandbox gateway" ||
			request.IdentityPublicKey == "" || request.WireGuardPublicKey == "" {
			t.Error("enrollment lost private input or public identity")
		}

		response := protocol.EnrolledDevice{
			ID:                  "gateway-1",
			Name:                request.Name,
			Role:                "gateway",
			Status:              "active",
			IdentityPublicKey:   request.IdentityPublicKey,
			WireGuardPublicKey:  request.WireGuardPublicKey,
			Credential:          "private-device-credential",
			CredentialExpiresAt: time.Now().Add(15 * time.Minute),
		}
		if amend != nil {
			amend(&response)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(f.server.Close)
	dir := t.TempDir()
	f.ca, f.state = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "gateway.json")

	if err := os.WriteFile(
		f.ca,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	return f
}

func (f *enrollFixture) run(ctx context.Context, extra ...string) (int, string, string) {
	command := NewCommand()

	command.SetIn(strings.NewReader(f.token + "\n"))
	args := append(
		[]string{
			"enroll",
			"--control",
			f.server.URL,
			"--ca-file",
			f.ca,
			"--state",
			f.state,
			"--name",
			"sandbox gateway",
		},
		extra...)
	var out, errOut bytes.Buffer

	code := host.Execute(ctx, args, &out, &errOut, command)

	return code, out.String(), errOut.String()
}

type denyAdmin struct{}

func (denyAdmin) AdminPrincipal(context.Context, *http.Request) (identity.Principal, error) {
	return identity.Principal{}, identity.ErrInvalidCredential
}

func TestGatewayEnrollUsesRealControlEnrollmentAndGatewayToken(t *testing.T) {
	for _, role := range []devices.Role{devices.RoleGateway, devices.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			service := devices.NewService(memorydevices.NewRepository(), time.Now, nil)

			token, err := service.IssueEnrollmentToken(context.Background(), role, time.Minute)
			if err != nil {
				t.Fatal(err)
			}

			api, err := httpapi.NewServer(httpapi.Dependencies{
				Resources: httpapi.ResourceDependencies{Devices: service},
				Security: httpapi.SecurityDependencies{
					Authorizer:    denyAdmin{},
					APILimiter:    httpapi.NewRateLimiter(100, time.Minute, time.Now),
					AuthLimiter:   httpapi.NewRateLimiter(100, time.Minute, time.Now),
					DeviceLimiter: httpapi.NewRateLimiter(100, time.Minute, time.Now),
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			f := newEnrollFixture(t, nil)
			f.token = token.Token

			handler := api.Handler()

			f.server.Config.Handler = http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					f.calls.Add(1)

					if r.URL.Path != "/api/v1/enroll" {
						t.Error("finite enrollment started runtime admission")
					}

					handler.ServeHTTP(w, r)
				},
			)

			code, out, errOut := f.run(context.Background())

			state, err := nodetest.Load(f.state)
			if err != nil {
				t.Fatal(err)
			}

			if f.calls.Load() != 1 || strings.Contains(out+errOut, token.Token) {
				t.Fatal("token replayed or disclosed")
			}

			if role == devices.RoleClient {
				if code == 0 || out != "" || state.DeviceID != "" {
					t.Fatal("client token admitted a gateway")
				}

				return
			}

			if code != 0 || state.DeviceID == "" || state.DeviceRole != "gateway" {
				t.Fatalf("real gateway enrollment failed: %d %s", code, errOut)
			}

			device, err := service.Authenticate(context.Background(), state.DeviceCredential)

			if err != nil || device.Role != devices.RoleGateway ||
				device.IdentityPublicKey != state.IdentityPublicKey ||
				device.WireGuardPublicKey != state.WireGuard.PublicKey {
				t.Fatal("stored credential/keys do not authenticate the control gateway")
			}
			if strings.Contains(out+errOut, state.DeviceCredential) {
				t.Fatal("real credential disclosed")
			}
		})
	}
}

func TestGatewayEnrollPersistsIdentityAndEmitsOnlyPublicJSON(t *testing.T) {
	f := newEnrollFixture(t, nil)

	code, out, errOut := f.run(context.Background())

	if code != 0 {
		t.Fatalf("enrollment failed: %d %s", code, errOut)
	}

	state, err := nodetest.Load(f.state)
	if err != nil {
		t.Fatal(err)
	}

	if state.DeviceID != "gateway-1" || state.DeviceCredential != "private-device-credential" ||
		state.CredentialExpiresAt.IsZero() ||
		f.calls.Load() != 1 {
		t.Fatal("enrollment did not persist one authoritative device")
	}

	var public map[string]string

	if err := json.Unmarshal([]byte(out), &public); err != nil {
		t.Fatal("public stdout is not JSON")
	}

	if len(public) != 3 || public["device_id"] != state.DeviceID ||
		public["identity_public_key"] != state.IdentityPublicKey ||
		public["wireguard_public_key"] != state.WireGuard.PublicKey {
		t.Fatal("public metadata does not describe persisted identity")
	}

	for _, secret := range []string{"private-gateway-token", state.DeviceCredential, state.IdentityPrivateKey, state.WireGuard.PrivateKey} {
		if strings.Contains(out+errOut, secret) {
			t.Fatal("enrollment exposed private input/state")
		}
	}

	before, err := os.ReadFile(f.state)
	if err != nil {
		t.Fatal(err)
	}

	f.server.Close()
	code, repeated, errOut := f.run(context.Background())

	if code != 0 || repeated != out || f.calls.Load() != 1 {
		t.Fatalf("repeat reenrolled or required control: %d %s", code, errOut)
	}

	after, err := os.ReadFile(f.state)

	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("repeat changed enrolled state")
	}
}

func TestGatewayEnrollRejectsWrongRoleKeyOrIncompleteResponse(t *testing.T) {
	for _, mode := range []string{"role", "identity", "wireguard", "credential", "expiry", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newEnrollFixture(t, func(device *protocol.EnrolledDevice) {
				switch mode {
				case "role":
					device.Role = "client"
				case "identity":
					device.IdentityPublicKey = "foreign"
				case "wireguard":
					device.WireGuardPublicKey = "foreign"
				case "credential":
					device.Credential = ""
				case "expiry":
					device.CredentialExpiresAt = time.Time{}
				case "expired":
					device.CredentialExpiresAt = time.Now().Add(-time.Minute)
				}
			})

			code, out, errOut := f.run(context.Background())

			if code == 0 || out != "" {
				t.Fatalf("invalid response accepted: %s", errOut)
			}

			state, err := nodetest.Load(f.state)

			if err != nil || state.DeviceID != "" || state.DeviceCredential != "" {
				t.Fatal("invalid response committed admission")
			}
			if strings.Contains(errOut, "private-device-credential") {
				t.Fatal("response error disclosed credential")
			}
		})
	}
}

func TestGatewayEnrollDoesNotExportPreviouslyJoinedClientAsGateway(t *testing.T) {
	f := newEnrollFixture(t, nil)

	state, err := node.NewState()
	if err != nil {
		t.Fatal(err)
	}

	// Older state has no durable role evidence. Reusing its credential must
	// not turn a joined client into public bootstrap metadata for a gateway.
	state.DeviceID, state.DeviceCredential = "client-1", "client-credential"

	if err := nodetest.Save(state, f.state); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(f.state)
	if err != nil {
		t.Fatal(err)
	}

	code, out, _ := f.run(context.Background())

	if code == 0 || out != "" || f.calls.Load() != 0 {
		t.Fatal("unverified existing role exported as gateway")
	}

	after, err := os.ReadFile(f.state)

	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected existing identity was rewritten")
	}
}

func TestGatewayEnrollDeadlineDoesNotCommitAdmission(t *testing.T) {
	f := newEnrollFixture(t, nil)
	var arrived atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.server.Config.Handler = http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		arrived.Store(true)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})

	code, out, errOut := f.run(context.Background(), "--timeout", "1s")

	if code == 0 || out != "" || !arrived.Load() || !strings.Contains(errOut, "deadline exceeded") {
		t.Fatalf("unbounded enrollment: %d %s", code, errOut)
	}

	state, err := nodetest.Load(f.state)

	if err != nil || state.DeviceID != "" || state.DeviceCredential != "" {
		t.Fatal("timed out enrollment committed admission")
	}
}

func TestGatewayEnrollRejectsActiveOrCorruptStateBeforeAdmission(t *testing.T) {
	for _, mode := range []string{"active", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			f := newEnrollFixture(t, nil)
			if mode == "active" {
				store, err := localstate.Open(f.state)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = store.Close() }()
			} else if err := os.WriteFile(f.state, []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}

			code, out, _ := f.run(context.Background())

			if code == 0 || out != "" || f.calls.Load() != 0 {
				t.Fatal("unsafe state reached admission")
			}
		})
	}
}

func TestGatewayEnrollHelpAndInvalidTrustDoNotCreateIdentity(t *testing.T) {
	f := newEnrollFixture(t, nil)
	for _, args := range [][]string{
		{"enroll", "--help", "--state", f.state, "--ca-file", "/missing"},
		{"enroll", "--state", f.state, "--control", "http://127.0.0.1", "--ca-file", f.ca},
		{"enroll", "--state", f.state, "--control", f.server.URL},
		{"enroll", "--state", f.state, "--control", f.server.URL, "--ca-file", f.ca, "--timeout", "0s"},
	} {
		var out, errOut bytes.Buffer

		code := host.Execute(context.Background(), args, &out, &errOut, NewCommand())

		if (args[1] == "--help") != (code == 0) {
			t.Fatalf("unexpected validation status: %d %s", code, errOut.String())
		}

		if _, err := os.Lstat(f.state); !os.IsNotExist(err) {
			t.Fatal("help/invalid trust created identity")
		}

		if f.calls.Load() != 0 {
			t.Fatal("help/invalid trust reached control")
		}
	}
}

func TestGatewayEnrollCanceledContextDoesNotCreateIdentity(t *testing.T) {
	f := newEnrollFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())

	cancel()
	code, out, _ := f.run(ctx)

	if code != 130 || out != "" || f.calls.Load() != 0 {
		t.Fatal("canceled finite enrollment reported success")
	}

	if _, err := os.Lstat(f.state); !os.IsNotExist(err) {
		t.Fatal("canceled enrollment created identity")
	}
}

func TestGatewayEnrollSavesSuccessfulResponseBeforeReportingCancellation(t *testing.T) {
	f := newEnrollFixture(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	command := &cobra.Command{}

	command.SetContext(ctx)
	command.SetIn(strings.NewReader(f.token + "\n"))
	var output bytes.Buffer

	command.SetOut(&output)
	options := enrollmentOptions{
		control: f.server.URL, ca: f.ca, state: f.state,
		name: "sandbox gateway", timeout: time.Minute,
	}

	err := enrollGatewayWith(command, options, func(
		_ context.Context, _ *http.Client, _ string, token, _ string, state *node.State,
	) error {
		if token != f.token || state.IdentityPublicKey == "" || state.WireGuard.PublicKey == "" {
			t.Fatal("enrollment did not use the existing local identity and private token")
		}

		state.DeviceID = "gateway-1"
		state.DeviceCredential = "private-device-credential"
		state.CredentialExpiresAt = time.Now().Add(15 * time.Minute)
		state.DeviceRole = "gateway"

		cancel() // The control response was validated, then the caller was canceled.
		return nil
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("late cancellation was not reported: %v", err)
	}

	stored, err := nodetest.Load(f.state)

	if err != nil || stored.DeviceID != "gateway-1" ||
		stored.DeviceCredential != "private-device-credential" || stored.DeviceRole != "gateway" {
		t.Fatalf("committed enrollment response was lost: %v", err)
	}
	if strings.Contains(output.String(), stored.DeviceCredential) {
		t.Fatal("credential disclosed after cancellation")
	}
}
