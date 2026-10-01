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

	if err := manager.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.1"),
		[]string{"Home.ARPA.", "cloud.home.arpa", "home.arpa"},
	); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"revert", "gt0"},
		{"default-route", "gt0", "false"},
		{"domain", "gt0", "~cloud.home.arpa", "~home.arpa"},
		{"dns", "gt0", "192.168.1.1"},
	}

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

	if err := manager.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.1"),
		[]string{"home.arpa"},
	); !errors.Is(
		err,
		failure,
	) {
		t.Fatalf("Apply() error=%v", err)
	}

	if !reflect.DeepEqual(
		commands,
		[]string{
			"revert gt0",
			"default-route gt0 false",
			"domain gt0 ~home.arpa",
			"dns gt0 192.168.1.1",
			"revert gt0",
		},
	) {
		t.Fatalf("commands=%#v", commands)
	}
}

func TestApplyRestoresPreviousSettingsAfterUpdateFailure(t *testing.T) {
	manager, err := NewManager("gt0")
	if err != nil {
		t.Fatal(err)
	}

	var commands []string
	secondApply := false
	manager.run = func(_ context.Context, args ...string) error {
		command := strings.Join(args, " ")
		commands = append(commands, command)
		if secondApply && command == "domain gt0 ~new.home.arpa" {
			return errors.New("domain update failed")
		}

		return nil
	}

	if err := manager.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.1"),
		[]string{"old.home.arpa"},
	); err != nil {
		t.Fatal(err)
	}

	commands = nil
	secondApply = true

	if err := manager.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.2"),
		[]string{"new.home.arpa"},
	); err == nil {
		t.Fatal("second Apply() error=nil")
	}

	want := []string{
		"revert gt0",
		"default-route gt0 false",
		"domain gt0 ~new.home.arpa",
		"revert gt0",
		"default-route gt0 false",
		"domain gt0 ~old.home.arpa",
		"dns gt0 192.168.1.1",
	}

	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands=%#v, want %#v", commands, want)
	}
}

func TestFailedRestorationRemainsDirtyUntilCloseSucceeds(t *testing.T) {
	m, _ := NewManager("wg0")
	fail := false
	var commands []string
	m.run = func(_ context.Context, args ...string) error {
		commands = append(commands, strings.Join(args, " "))
		if fail && args[0] == "dns" {
			return errors.New("resolver failure")
		}

		return nil
	}

	if err := m.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.1"),
		[]string{"home.arpa"},
	); err != nil {
		t.Fatal(err)
	}

	fail = true

	if err := m.Apply(
		context.Background(),
		netip.MustParseAddr("192.168.1.2"),
		[]string{"new.home.arpa"},
	); err == nil {
		t.Fatal("expected failed update and restoration")
	}

	commands = nil
	fail = false

	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(commands, []string{"revert wg0"}) {
		t.Fatalf("dirty DNS state was abandoned: %v", commands)
	}
}

func TestCanonicalSuffixesRejectsInjectionCharacters(t *testing.T) {
	if _, err := canonicalSuffixes([]string{"home.arpa;resolvectl"}); err == nil {
		t.Fatal("canonicalSuffixes() error=nil")
	}
}
