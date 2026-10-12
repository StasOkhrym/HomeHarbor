package macos

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StasOkhrym/homeharbor/internal/node/networkplan"
)

type effectCall struct {
	path string
	args []string
}

type fakeEffectRunner struct {
	calls  []effectCall
	output string
}

func (f *fakeEffectRunner) Run(_ context.Context, path string, args ...string) (string, error) {
	f.calls = append(f.calls, effectCall{path, append([]string(nil), args...)})
	return f.output, nil
}

func TestDarwinEffectsUseExactNativeArgumentsAndScopedRoutes(t *testing.T) {
	authority, _, _ := nativeFixture(t)
	runner := &fakeEffectRunner{output: `   route to: 172.29.50.0
destination: 172.29.50.0
       mask: 255.255.255.0
  interface: utun7
`}

	effects, err := newDarwinEffects(authority, t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	address := netip.MustParsePrefix("10.200.0.3/32")

	route := netip.MustParsePrefix("172.29.50.0/24")

	if err := effects.Address(ctx, "utun7", address); err != nil {
		t.Fatal(err)
	}

	if err := effects.AddRoute(ctx, "utun7", route); err != nil {
		t.Fatal(err)
	}

	if err := effects.RemoveRoute(ctx, "utun7", route); err != nil {
		t.Fatal(err)
	}

	want := []effectCall{
		{"/sbin/ifconfig", []string{"utun7", "inet", "10.200.0.3/32", "10.200.0.3", "alias"}},
		{"/sbin/ifconfig", []string{"utun7", "up"}},
		{
			"/sbin/route",
			[]string{"-q", "-n", "add", "-inet", "172.29.50.0/24", "-interface", "utun7"},
		},
		{"/sbin/route", []string{"-n", "get", "-inet", "172.29.50.0/24"}},
		{"/sbin/route", []string{"-q", "-n", "delete", "-inet", "172.29.50.0/24"}},
	}

	if len(runner.calls) != len(want) {
		t.Fatalf("native calls = %+v", runner.calls)
	}

	for i := range want {
		if runner.calls[i].path != want[i].path ||
			strings.Join(runner.calls[i].args, "\x00") != strings.Join(want[i].args, "\x00") {
			t.Fatalf("native call %d = %+v; want %+v", i, runner.calls[i], want[i])
		}
	}

	before := len(runner.calls)
	for _, invalid := range []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("203.0.113.0/24"),
	} {
		if err := effects.AddRoute(ctx, "utun7", invalid); err == nil {
			t.Fatalf("unsafe route accepted: %s", invalid)
		}
	}

	if err := effects.AddRoute(ctx, "utun7;touch /tmp/escaped", route); err == nil {
		t.Fatal("shell payload accepted as interface name")
	}

	if len(runner.calls) != before {
		t.Fatalf("unsafe input reached native runner: %+v", runner.calls[before:])
	}

	runner.output = strings.ReplaceAll(runner.output, "utun7", "en0")

	if err := effects.RemoveRoute(ctx, "utun7", route); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("foreign route deleted: %v", err)
	}

	if len(runner.calls) != before+1 {
		t.Fatalf("foreign route triggered mutation: %+v", runner.calls[before:])
	}
}

func TestDarwinResolverPreservesForeignContentAndOnlyOwnsSignedSuffix(t *testing.T) {
	authority, _, _ := nativeFixture(t)
	dir := t.TempDir()

	effects, err := newDarwinEffects(authority, dir, &fakeEffectRunner{})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	resolver := networkplan.Resolver{
		Suffix: "sandbox.home.arpa", Address: netip.MustParseAddr("172.29.50.53"),
	}
	path := filepath.Join(dir, resolver.Suffix)

	if err := os.WriteFile(path, []byte("nameserver 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := effects.SetDNS(ctx, resolver); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("foreign scoped DNS overwritten: %v", err)
	}

	if err := effects.RemoveDNS(ctx, resolver); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("foreign scoped DNS removed: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err := effects.SetDNS(ctx, resolver); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)

	if err != nil || !strings.Contains(string(content), "nameserver 172.29.50.53\n") {
		t.Fatalf("scoped resolver content = %q, err=%v", content, err)
	}

	if err := effects.RemoveDNS(ctx, resolver); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned resolver remains: %v", err)
	}

	if err := effects.SetDNS(ctx, networkplan.Resolver{
		Suffix: "example.com", Address: resolver.Address,
	}); err == nil {
		t.Fatal("foreign resolver suffix accepted")
	}
}

func TestDarwinRouteCleanupPreservesBroaderSelectedRoute(t *testing.T) {
	authority, _, _ := nativeFixture(t)
	runner := &fakeEffectRunner{output: `destination: default
  interface: en0
`}

	effects, err := newDarwinEffects(authority, t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}

	if err := effects.RemoveRoute(
		context.Background(),
		"utun7",
		netip.MustParsePrefix("172.29.50.0/24"),
	); err != nil {
		t.Fatal(err)
	}

	if len(runner.calls) != 1 || runner.calls[0].args[1] != "get" {
		t.Fatalf("cleanup mutated a broader route: %+v", runner.calls)
	}
}

func TestDarwinResolverRejectsSymlink(t *testing.T) {
	authority, _, _ := nativeFixture(t)
	dir := t.TempDir()

	effects, err := newDarwinEffects(authority, dir, &fakeEffectRunner{})
	if err != nil {
		t.Fatal(err)
	}

	foreign := filepath.Join(t.TempDir(), "foreign")

	if err := os.WriteFile(foreign, []byte("nameserver 192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(foreign, filepath.Join(dir, "sandbox.home.arpa")); err != nil {
		t.Fatal(err)
	}

	resolver := networkplan.Resolver{
		Suffix:  "sandbox.home.arpa",
		Address: netip.MustParseAddr("172.29.50.53"),
	}

	if err := effects.SetDNS(
		context.Background(),
		resolver,
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("symlink resolver accepted: %v", err)
	}

	if err := effects.RemoveDNS(
		context.Background(),
		resolver,
	); !errors.Is(
		err,
		ErrOwnershipConflict,
	) {
		t.Fatalf("symlink resolver removed: %v", err)
	}

	content, err := os.ReadFile(foreign)

	if err != nil || string(content) != "nameserver 192.0.2.1\n" {
		t.Fatalf("foreign resolver changed: %q, %v", content, err)
	}
}

func TestNativeRunnerRejectsCallerExecutable(t *testing.T) {
	if _, err := (nativeCommandRunner{}).Run(
		context.Background(),
		"/bin/sh",
		"-c",
		"exit 0",
	); err == nil {
		t.Fatal("native effect runner accepted caller executable")
	}
}

func TestDarwinEffectsRejectUnboundedProvisioning(t *testing.T) {
	authority, _, _ := nativeFixture(t)
	for _, unsafe := range []networkplan.Bounds{
		{Overlay: netip.MustParsePrefix("0.0.0.0/0"), Private: authority.Bounds.Private, Suffix: authority.Bounds.Suffix},
		{Overlay: authority.Bounds.Overlay, Private: netip.MustParsePrefix("0.0.0.0/0"), Suffix: authority.Bounds.Suffix},
		{Overlay: authority.Bounds.Private, Private: authority.Bounds.Private, Suffix: authority.Bounds.Suffix},
	} {
		candidate := authority
		candidate.Bounds = unsafe

		if _, err := newDarwinEffects(candidate, t.TempDir(), &fakeEffectRunner{}); err == nil {
			t.Fatalf("unsafe native bounds accepted: %+v", unsafe)
		}
	}
}

func TestDarwinRouteLookupAcceptsHexMask(t *testing.T) {
	prefix, name, err := parseDarwinRoute(
		"destination: 172.29.50.0\nmask: 0xffffff00\ninterface: utun7\n",
	)

	if err != nil || prefix != netip.MustParsePrefix("172.29.50.0/24") || name != "utun7" {
		t.Fatalf("hex route mask parsed as %s %q, err=%v", prefix, name, err)
	}
}
