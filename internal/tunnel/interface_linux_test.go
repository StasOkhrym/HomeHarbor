//go:build linux

package tunnel

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func TestEnsureLinuxInterfaceReconcilesIdempotently(t *testing.T) {
	original := ipRunner
	t.Cleanup(func() { ipRunner = original })
	var commands [][]string
	ipRunner = func(_ context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		if len(commands) == 1 {
			return errors.New("interface does not exist")
		}
		return nil
	}
	if err := EnsureLinuxInterface(context.Background(), "gt0", "100.64.0.1/32", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"link", "show", "dev", "gt0"},
		{"link", "add", "dev", "gt0", "type", "wireguard"},
		{"address", "replace", "100.64.0.1/32", "dev", "gt0"},
		{"link", "set", "dev", "gt0", "up"},
		{"route", "replace", "10.0.0.0/8", "dev", "gt0"},
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands=%#v, want %#v", commands, want)
	}
}

func TestEnsureLinuxInterfaceRejectsDefaultRouteBeforeCommands(t *testing.T) {
	original := ipRunner
	t.Cleanup(func() { ipRunner = original })
	called := false
	ipRunner = func(context.Context, ...string) error {
		called = true
		return nil
	}
	if err := EnsureLinuxInterface(context.Background(), "gt0", "100.64.0.1/32", []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}); err == nil {
		t.Fatal("default route was accepted")
	}
	if called {
		t.Fatal("ip command ran before route validation")
	}
}

func TestEnableLinuxForwardingUsesExplicitSysctls(t *testing.T) {
	original := sysctlRunner
	t.Cleanup(func() { sysctlRunner = original })
	var commands [][]string
	sysctlRunner = func(_ context.Context, args ...string) error {
		commands = append(commands, append([]string(nil), args...))
		return nil
	}

	if err := EnableLinuxForwarding(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"-w", "net.ipv4.ip_forward=1"}, {"-w", "net.ipv6.conf.all.forwarding=1"}}

	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands=%#v, want %#v", commands, want)
	}
}
