package dns

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestApplyCanonicalizesSuffixesAndCloseReverts(t *testing.T) {
	manager, err := NewManager("gt0")
	if err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	manager.run = func(_ context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	}
	if err := manager.Apply(context.Background(), netip.MustParseAddr("192.168.1.1"), []string{"Home.ARPA.", "cloud.home.arpa", "home.arpa"}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"revert", "gt0"}, {"dns", "gt0", "192.168.1.1"}, {"domain", "gt0", "~cloud.home.arpa"}, {"domain", "gt0", "~home.arpa"}, {"default-route", "gt0", "false"}}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands=%#v, want %#v", commands, want)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := commands[len(commands)-1]; !reflect.DeepEqual(got, []string{"revert", "gt0"}) {
		t.Fatalf("close command=%#v", got)
	}
}

func TestApplyRevertsAfterResolverFailure(t *testing.T) {
	manager, err := NewManager("gt0")
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("resolver unavailable")
	var commands []string
	manager.run = func(_ context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		if len(args) > 0 && args[0] == "dns" {
			return failure
		}
		return nil
	}
	if err := manager.Apply(context.Background(), netip.MustParseAddr("192.168.1.1"), []string{"home.arpa"}); !errors.Is(err, failure) {
		t.Fatalf("Apply() error=%v", err)
	}
	if !reflect.DeepEqual(commands, []string{"revert gt0", "dns gt0 192.168.1.1", "revert gt0"}) {
		t.Fatalf("commands=%#v", commands)
	}
}

func TestCanonicalSuffixesRejectsInjectionCharacters(t *testing.T) {
	if _, err := canonicalSuffixes([]string{"home.arpa;resolvectl"}); err == nil {
		t.Fatal("canonicalSuffixes() error=nil")
	}
}
