package macos

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
	"github.com/StasOkhrym/homeharbor/internal/snapshot"
)

type fakeNative struct {
	calls         []string
	failAt        string
	externalRoute bool
	externalDNS   bool
	created       bool
	interfaceName string
}

func (f *fakeNative) call(name string) error {
	f.calls = append(f.calls, name)
	if name == f.failAt {
		return errors.New("injected native failure")
	}

	return nil
}

func (f *fakeNative) Prepare(context.Context, networkplan.Plan) error { return f.call("prepare") }
func (f *fakeNative) Create(context.Context, string) (string, error) {
	if err := f.call("create"); err != nil {
		return "", err
	}

	f.created = true
	if f.interfaceName != "" {
		return f.interfaceName, nil
	}

	return "utun7", nil
}

func (f *fakeNative) ResolveCreated(context.Context, string) (string, error) {
	if !f.created {
		return "", nil
	}

	return "utun7", f.call("resolve-created")
}

func (f *fakeNative) Configure(context.Context, string, networkplan.Plan) error {
	return f.call("configure")
}

func (f *fakeNative) Address(context.Context, string, netip.Prefix) error {
	return f.call("address")
}

func (f *fakeNative) AddRoute(context.Context, string, netip.Prefix) error {
	return f.call("route")
}

func (f *fakeNative) SetDNS(context.Context, networkplan.Resolver) error {
	return f.call("dns")
}

func (f *fakeNative) RemoveDNS(context.Context, networkplan.Resolver) error {
	if f.externalDNS {
		return ErrOwnershipConflict
	}

	return f.call("remove-dns")
}

func (f *fakeNative) RemoveRoute(context.Context, string, netip.Prefix) error {
	if f.externalRoute {
		return ErrOwnershipConflict
	}

	return f.call("remove-route")
}

func (f *fakeNative) CloseTunnel(context.Context, string) error {
	if err := f.call("close-tunnel"); err != nil {
		return err
	}

	f.created = false

	return nil
}

func nativeFixture(t *testing.T) (Authority, snapshot.Envelope, networkplan.Plan) {
	authority, envelope, plan, _ := nativeFixtureWithKey(t)
	return authority, envelope, plan
}

func nativeFixtureWithKey(t *testing.T) (
	Authority, snapshot.Envelope, networkplan.Plan, ed25519.PrivateKey,
) {
	t.Helper()
	root, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bounds := networkplan.Bounds{
		Overlay: netip.MustParsePrefix("10.200.0.0/24"),
		Private: netip.MustParsePrefix("172.29.50.0/24"),
		Suffix:  "sandbox.home.arpa",
	}
	value := snapshot.NetworkSnapshot{
		NetworkID: "sandbox-network",
		Revision:  1,
		Devices: []snapshot.Device{
			{
				ID:                 "client-1",
				Role:               "client",
				WireGuardPublicKey: client.PublicKey().String(),
				OverlayAddress:     "10.200.0.3/32",
			},
			{
				ID:                 "gateway-1",
				Role:               "gateway",
				WireGuardPublicKey: gateway.PublicKey().String(),
				OverlayAddress:     "10.200.0.2/32",
			},
		},
		Gateways: []snapshot.Gateway{{DeviceID: "gateway-1"}},
		Routes: []snapshot.Route{
			{
				ID:           "site",
				GatewayID:    "gateway-1",
				Prefix:       "172.29.50.0/24",
				DomainSuffix: bounds.Suffix,
				Resolver:     "172.29.50.53",
			},
		},
	}
	envelope, err := snapshot.Sign(value, signing, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	authority := Authority{
		Root:      root,
		NetworkID: value.NetworkID,
		DeviceID:  "client-1",
		Bounds:    bounds,
	}
	plan, err := networkplan.CompileSigned(envelope, root, value.NetworkID, "client-1", bounds)
	if err != nil {
		t.Fatal(err)
	}
	return authority, envelope, plan, signing
}

func TestPartialApplyKeepsRevision(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	native := &fakeNative{failAt: "dns"}
	journal := filepath.Join(t.TempDir(), "owner.json")
	adapter := NewAdapter(journal, authority, envelope, native)
	if err := adapter.Apply(context.Background(), plan); err == nil {
		t.Fatal("partial native apply succeeded")
	}
	state, err := readJournal(journal)
	if err != nil || state.AppliedRevision == plan.Revision {
		t.Fatalf("partial apply advanced revision: state=%+v err=%v", state, err)
	}
	if !slices.Contains(native.calls, "remove-route") ||
		!slices.Contains(native.calls, "close-tunnel") {
		t.Fatalf("partial apply did not roll back owned state: %v", native.calls)
	}
}

func TestCleanupPreservesExternalChanges(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	native := &fakeNative{}
	journal := filepath.Join(t.TempDir(), "owner.json")
	adapter := NewAdapter(journal, authority, envelope, native)
	if err := adapter.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	native.externalDNS = true
	if err := adapter.Close(context.Background()); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("externally replaced DNS was overwritten or silently ignored: %v", err)
	}
	state, err := readJournal(journal)
	if err != nil || len(state.DNS) == 0 {
		t.Fatalf("conflict lost recovery journal: state=%+v err=%v", state, err)
	}
}

func TestJournalRecoversInterruptedApply(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	native := &fakeNative{failAt: "route", externalRoute: true}
	journal := filepath.Join(t.TempDir(), "owner.json")
	adapter := NewAdapter(journal, authority, envelope, native)
	if err := adapter.Apply(context.Background(), plan); err == nil {
		t.Fatal("partial route failure accepted")
	}
	state, err := readJournal(journal)
	if err != nil || len(state.Routes) == 0 {
		t.Fatalf("interrupted apply lost route ownership: state=%+v err=%v", state, err)
	}
	native.externalRoute = false
	native.failAt = ""
	if err := NewAdapter(
		journal,
		authority,
		envelope,
		native,
	).Close(context.Background()); err != nil {
		t.Fatalf("new process could not recover owned route: %v", err)
	}
}

func TestNativeArgumentsCannotExecuteShell(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	native := &fakeNative{interfaceName: "utun7;touch /tmp/escaped"}
	adapter := NewAdapter(filepath.Join(t.TempDir(), "owner.json"), authority, envelope, native)
	if err := adapter.Apply(context.Background(), plan); err == nil {
		t.Fatal("untrusted native interface name accepted")
	}
	if slices.Contains(native.calls, "configure") || slices.Contains(native.calls, "address") ||
		slices.Contains(native.calls, "route") || slices.Contains(native.calls, "dns") {
		t.Fatalf("untrusted interface name reached native command arguments: %v", native.calls)
	}
}

func TestHelperRejectsChangedPlanBeforeNativeEffects(t *testing.T) {
	authority, envelope, plan := nativeFixture(t)
	plan.Routes[0] = netip.MustParsePrefix("172.29.50.80/32")
	native := &fakeNative{}
	adapter := NewAdapter(filepath.Join(t.TempDir(), "owner.json"), authority, envelope, native)
	if err := adapter.Apply(context.Background(), plan); err == nil {
		t.Fatal("caller changed route after signed compilation")
	}
	if len(native.calls) != 0 {
		t.Fatalf("untrusted plan caused native effects: %v", native.calls)
	}
}

func TestFailedNewRevisionCannotReopenOldPolicy(t *testing.T) {
	authority, firstEnvelope, firstPlan, signing := nativeFixtureWithKey(t)
	native := &fakeNative{}
	journal := filepath.Join(t.TempDir(), "owner.json")
	if err := NewAdapter(journal, authority, firstEnvelope, native).
		Apply(context.Background(), firstPlan); err != nil {
		t.Fatal(err)
	}
	secondValue, err := snapshot.Decode(firstEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	secondValue.Revision = 2
	secondValue.PreviousHash = firstEnvelope.Hash
	secondEnvelope, err := snapshot.Sign(secondValue, signing, "root-1")
	if err != nil {
		t.Fatal(err)
	}
	secondPlan, err := networkplan.CompileSigned(
		secondEnvelope, authority.Root, authority.NetworkID, authority.DeviceID, authority.Bounds,
	)
	if err != nil {
		t.Fatal(err)
	}
	native.failAt = "dns"
	if err := NewAdapter(journal, authority, secondEnvelope, native).
		Apply(context.Background(), secondPlan); err == nil {
		t.Fatal("injected new revision failure was accepted")
	}
	native.failAt = ""
	before := len(native.calls)
	if err := NewAdapter(journal, authority, firstEnvelope, native).
		Apply(context.Background(), firstPlan); err == nil {
		t.Fatal("old signed policy reopened access after newer revision failed")
	}
	if len(native.calls) != before {
		t.Fatalf("old revision reached native operations: %v", native.calls[before:])
	}
}
