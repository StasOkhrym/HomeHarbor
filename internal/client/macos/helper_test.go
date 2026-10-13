package macos

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func helperJSON(t *testing.T, request HelperRequest) []byte {
	t.Helper()

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	return encoded
}

func testLocalPublicKey(t *testing.T, private string) string {
	t.Helper()

	key, err := wgtypes.ParseKey(private)
	if err != nil {
		t.Fatal(err)
	}

	return key.PublicKey().String()
}

func TestHelperAppliesOnlyExactSignedPlanForProvisionedOwner(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)
	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	request := HelperRequest{
		Version:    1,
		Action:     "apply",
		Envelope:   envelope,
		Plan:       plan,
		PrivateKey: privateKey,
	}
	native := &fakeNative{}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		502,
		native,
	); err == nil {
		t.Fatal("foreign UID applied native networking")
	}

	if len(native.calls) != 0 {
		t.Fatalf("foreign UID caused native effects: %v", native.calls)
	}

	originalRoute := request.Plan.Routes[0]

	request.Plan.Routes[0] = netip.MustParsePrefix("172.29.50.80/32")

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("changed plan passed the signed helper boundary")
	}

	if len(native.calls) != 0 {
		t.Fatalf("changed plan caused native effects: %v", native.calls)
	}

	request.Plan.Routes[0] = originalRoute

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err != nil {
		t.Fatalf("exact signed plan rejected: %v", err)
	}

	if len(native.calls) == 0 {
		t.Fatal("valid helper request did not apply native operations")
	}
	if native.configuredTunnel.PrivateKey != privateKey ||
		native.configuredTunnel.BridgeEndpoint != policy.Tunnel.BridgeEndpoint ||
		native.configuredTunnel.ListenPort != policy.Tunnel.ListenPort {
		t.Fatal("verified WireGuard identity was not passed to native configuration")
	}
}

func TestHelperRejectsUnboundedOrAmbiguousInputBeforeEffects(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)
	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}

	request := helperJSON(
		t,
		HelperRequest{
			Version:    1,
			Action:     "apply",
			Envelope:   envelope,
			Plan:       plan,
			PrivateKey: privateKey,
		},
	)
	for _, input := range [][]byte{
		append(bytes.Clone(request), []byte(` {"version":1,"action":"close"}`)...),
		[]byte(`{"version":1,"version":1,"action":"close"}`),
		append(bytes.Clone(request[:len(request)-1]), []byte(`,"shell":"touch /tmp/escaped"}`)...),
		[]byte(strings.Repeat(" ", MaxHelperRequestBytes+1)),
	} {
		native := &fakeNative{}

		if err := ExecuteHelper(
			context.Background(),
			bytes.NewReader(input),
			policy,
			501,
			native,
		); err == nil {
			t.Fatal("malformed or oversized helper request accepted")
		}

		if len(native.calls) != 0 {
			t.Fatalf("malformed request caused native effects: %v", native.calls)
		}
	}
}

func TestHelperRejectsPrivateKeyForAnotherSignedDevice(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)

	foreignKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	native := &fakeNative{}
	request := HelperRequest{
		Version: 1, Action: "apply", Envelope: envelope, Plan: plan,
		PrivateKey: foreignKey.String(),
	}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("foreign WireGuard identity reached native operations")
	}

	if len(native.calls) != 0 {
		t.Fatalf("foreign WireGuard identity caused effects: %v", native.calls)
	}
}

func TestHelperCloseCannotCarryAnUnsignedPlan(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)
	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	native := &fakeNative{}
	request := HelperRequest{
		Version:  1,
		Action:   "close",
		Owner:    helperOwner(authority),
		Envelope: envelope,
		Plan:     plan,
	}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("close accepted a caller-selected plan")
	}

	if len(native.calls) != 0 {
		t.Fatalf("invalid close caused native effects: %v", native.calls)
	}
}

func TestHelperRejectsSignedDeviceThatDiffersFromRootPinnedIdentity(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)

	foreign, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	policy := HelperPolicy{
		Authority: authority, OwnerUID: 501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: foreign.PublicKey().String(),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	request := HelperRequest{
		Version: 1, Action: "apply", Envelope: envelope, Plan: plan,
		PrivateKey: privateKey,
	}
	native := &fakeNative{}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, request)),
		policy,
		501,
		native,
	); err == nil {
		t.Fatal("signed but foreign local WireGuard key bypassed provisioned identity")
	}

	if len(native.calls) != 0 {
		t.Fatalf("foreign local key caused host effects: %v", native.calls)
	}
}

type policyHelperExecutor struct {
	policy HelperPolicy
	ops    Operations
}

func (h policyHelperExecutor) Execute(ctx context.Context, request HelperRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	return ExecuteHelper(ctx, bytes.NewReader(data), h.policy, h.policy.OwnerUID, h.ops)
}

func TestControllerCloseRejectsAnotherConfiguredOwnerBeforeCleanup(t *testing.T) {
	authority, envelope, plan, _, privateKey := nativeFixtureWithKey(t)
	policy := HelperPolicy{
		Authority:               authority,
		OwnerUID:                501,
		JournalPath:             filepath.Join(t.TempDir(), "owner.json"),
		LocalWireGuardPublicKey: testLocalPublicKey(t, privateKey),
		Tunnel: TunnelConfig{
			BridgeEndpoint: netip.MustParseAddrPort("127.0.0.1:51822"),
			ListenPort:     51820,
		},
	}
	native := &fakeNative{}
	apply := HelperRequest{
		Version:    1,
		Action:     "apply",
		Envelope:   envelope,
		Plan:       plan,
		PrivateKey: privateKey,
	}

	if err := ExecuteHelper(
		context.Background(),
		bytes.NewReader(helperJSON(t, apply)),
		policy,
		501,
		native,
	); err != nil {
		t.Fatal(err)
	}

	before := len(native.calls)
	helper := policyHelperExecutor{policy: policy, ops: native}
	for _, mutate := range []func(*Authority){
		func(a *Authority) { a.NetworkID = "another-network" },
		func(a *Authority) { a.DeviceID = "another-device" },
		func(a *Authority) { a.Root = append(a.Root[:0:0], a.Root...); a.Root[0] ^= 1 },
	} {
		foreign := authority

		mutate(&foreign)

		controller, err := NewController(foreign, privateKey, time.Second, helper)
		if err != nil {
			t.Fatal(err)
		}

		if err := controller.Close(context.Background()); err == nil {
			t.Fatal("foreign configured owner closed installed native ownership")
		}

		if len(native.calls) != before {
			t.Fatal("foreign configured owner reached native cleanup")
		}
	}

	controller, err := NewController(authority, privateKey, time.Second, helper)
	if err != nil {
		t.Fatal(err)
	}

	if err := controller.Close(context.Background()); err != nil {
		t.Fatalf("correctly scoped owner could not clean up: %v", err)
	}
}
