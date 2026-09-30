//go:build linux

package acceptance

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sokhrym/go-tunnels/internal/agent/nft"
	"github.com/sokhrym/go-tunnels/internal/control/policy"
)

func TestLinuxNamespaceDefaultDenyLANAccess(t *testing.T) {
	requireNetworkTools(t, false)

	suffix := fmt.Sprintf("%d", os.Getpid())
	clientNS := "gt-client-" + suffix
	gatewayNS := "gt-gateway-" + suffix
	lanNS := "gt-lan-" + suffix
	for _, namespace := range []string{clientNS, gatewayNS, lanNS} {
		if err := run("ip", "netns", "add", namespace); err != nil {
			if strings.Contains(err.Error(), "Operation not permitted") || strings.Contains(err.Error(), "Permission denied") {
				t.Skipf("network namespaces are unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, namespace := range []string{clientNS, gatewayNS, lanNS} {
			_ = run("ip", "netns", "del", namespace)
		}
	})

	createVethTopology(t, clientNS, gatewayNS, lanNS)
	configureTopology(t, clientNS, gatewayNS, lanNS, true)
	servers := startHTTPServers(t, lanNS)
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	})

	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	waitForHTTP(t, clientNS, "http://192.168.50.2:8081")

	peers := map[string]netip.Prefix{"client": netip.MustParsePrefix("100.64.0.2/32")}
	rules := policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{
		ID:             "allow-http",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       8080,
		PortTo:         8080,
	}}}
	applyDefaultDenyPolicy(t, gatewayNS, "gt0", peers, rules)

	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	if err := curl(clientNS, "http://192.168.50.2:8081"); err == nil {
		t.Fatal("default-deny policy allowed a forbidden port")
	}
}

func TestLinuxNamespaceKernelWireGuardDefaultDenyLANAccess(t *testing.T) {
	requireNetworkTools(t, true)

	suffix := fmt.Sprintf("%d-wg", os.Getpid())
	clientNS := "gt-client-" + suffix
	gatewayNS := "gt-gateway-" + suffix
	lanNS := "gt-lan-" + suffix
	for _, namespace := range []string{clientNS, gatewayNS, lanNS} {
		if err := run("ip", "netns", "add", namespace); err != nil {
			if strings.Contains(err.Error(), "Operation not permitted") || strings.Contains(err.Error(), "Permission denied") {
				t.Skipf("network namespaces are unavailable: %v", err)
			}
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, namespace := range []string{clientNS, gatewayNS, lanNS} {
			_ = run("ip", "netns", "del", namespace)
		}
	})

	createVethTopology(t, clientNS, gatewayNS, lanNS)
	configureTopology(t, clientNS, gatewayNS, lanNS, false)
	configureWireGuard(t, clientNS, gatewayNS)
	servers := startHTTPServers(t, lanNS)
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	})

	// The first request proves the encrypted kernel path works before the
	// gateway firewall is installed; the policy assertion below then proves
	// that the source identity is the WireGuard overlay address, not the veth.
	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	peers := map[string]netip.Prefix{"client": netip.MustParsePrefix("10.200.0.2/32")}
	rules := policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{
		ID:             "allow-http",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       8080,
		PortTo:         8080,
	}}}
	applyDefaultDenyPolicy(t, gatewayNS, "wg0", peers, rules)

	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	if err := curl(clientNS, "http://192.168.50.2:8081"); err == nil {
		t.Fatal("default-deny policy allowed a forbidden WireGuard port")
	}
}

func requireNetworkTools(t *testing.T, wireGuard bool) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("network namespace acceptance requires root or CAP_NET_ADMIN")
	}
	commands := []string{"ip", "nft", "curl", "python3"}
	if wireGuard {
		commands = append(commands, "wg")
	}
	for _, command := range commands {
		if _, err := exec.LookPath(command); err != nil {
			t.Skipf("%s is not installed", command)
		}
	}
}

func applyDefaultDenyPolicy(t *testing.T, namespace, interfaceName string, peers map[string]netip.Prefix, rules policy.Snapshot) {
	t.Helper()
	script, err := nft.Compile(interfaceName, peers, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := runWithInput(namespace, script, "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

func configureWireGuard(t *testing.T, clientNS, gatewayNS string) {
	t.Helper()
	clientPrivate, clientPublic := generateWireGuardKey(t)
	gatewayPrivate, gatewayPublic := generateWireGuardKey(t)

	for _, setup := range [][]string{
		{clientNS, "ip", "link", "add", "wg0", "type", "wireguard"},
		{gatewayNS, "ip", "link", "add", "wg0", "type", "wireguard"},
		{clientNS, "ip", "address", "add", "10.200.0.2/32", "dev", "wg0"},
		{gatewayNS, "ip", "address", "add", "10.200.0.1/32", "dev", "wg0"},
		{clientNS, "ip", "link", "set", "wg0", "up"},
		{gatewayNS, "ip", "link", "set", "wg0", "up"},
	} {
		if err := runInNamespace(setup[0], setup[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	if err := runWithInput(gatewayNS, gatewayPrivate+"\n", "wg", "set", "wg0", "private-key", "/dev/stdin", "listen-port", "51820", "peer", clientPublic, "allowed-ips", "10.200.0.2/32", "endpoint", "100.64.0.2:51820", "persistent-keepalive", "25"); err != nil {
		t.Fatal(err)
	}
	if err := runWithInput(clientNS, clientPrivate+"\n", "wg", "set", "wg0", "private-key", "/dev/stdin", "listen-port", "51820", "peer", gatewayPublic, "allowed-ips", "192.168.50.0/24", "endpoint", "100.64.0.1:51820", "persistent-keepalive", "25"); err != nil {
		t.Fatal(err)
	}
	if err := runInNamespace(gatewayNS, "ip", "route", "add", "10.200.0.2/32", "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := runInNamespace(clientNS, "ip", "route", "add", "192.168.50.0/24", "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
}

func generateWireGuardKey(t *testing.T) (private, public string) {
	t.Helper()
	private = strings.TrimSpace(commandOutput(t, "wg", "genkey"))
	public = strings.TrimSpace(commandOutputWithInput(t, private+"\n", "wg", "pubkey"))

	return private, public
}

func createVethTopology(t *testing.T, clientNS, gatewayNS, lanNS string) {
	t.Helper()
	if err := run("ip", "link", "add", "gt-client-peer", "type", "veth", "peer", "name", "gt0"); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", "gt-client-peer", "netns", clientNS); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", "gt0", "netns", gatewayNS); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "add", "gt-lan-peer", "type", "veth", "peer", "name", "lan0"); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", "gt-lan-peer", "netns", gatewayNS); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", "lan0", "netns", lanNS); err != nil {
		t.Fatal(err)
	}
}

func configureTopology(t *testing.T, clientNS, gatewayNS, lanNS string, routeLANViaOuterNetwork bool) {
	t.Helper()
	commands := [][]string{
		{clientNS, "ip", "link", "set", "lo", "up"},
		{gatewayNS, "ip", "link", "set", "lo", "up"},
		{lanNS, "ip", "link", "set", "lo", "up"},
		{clientNS, "ip", "addr", "add", "100.64.0.2/24", "dev", "gt-client-peer"},
		{gatewayNS, "ip", "addr", "add", "100.64.0.1/24", "dev", "gt0"},
		{gatewayNS, "ip", "addr", "add", "192.168.50.1/24", "dev", "gt-lan-peer"},
		{lanNS, "ip", "addr", "add", "192.168.50.2/24", "dev", "lan0"},
		{clientNS, "ip", "link", "set", "gt-client-peer", "up"},
		{gatewayNS, "ip", "link", "set", "gt0", "up"},
		{gatewayNS, "ip", "link", "set", "gt-lan-peer", "up"},
		{lanNS, "ip", "link", "set", "lan0", "up"},
		{lanNS, "ip", "route", "add", "100.64.0.0/24", "via", "192.168.50.1"},
		{gatewayNS, "sysctl", "-w", "net.ipv4.ip_forward=1"},
	}
	if routeLANViaOuterNetwork {
		commands = append(commands, []string{clientNS, "ip", "route", "add", "192.168.50.0/24", "via", "100.64.0.1"})
	}
	for _, command := range commands {
		if err := runInNamespace(command[0], command[1:]...); err != nil {
			t.Fatal(err)
		}
	}
}

func startHTTPServers(t *testing.T, namespace string) []*exec.Cmd {
	t.Helper()
	servers := make([]*exec.Cmd, 0, 2)
	for _, port := range []string{"8080", "8081"} {
		server := exec.Command("ip", "netns", "exec", namespace, "python3", "-m", "http.server", port, "--bind", "192.168.50.2")
		server.Stdout = io.Discard
		server.Stderr = io.Discard
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		servers = append(servers, server)
	}
	return servers
}

func waitForHTTP(t *testing.T, namespace, address string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if curl(namespace, address) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("HTTP service %s was not reachable", address)
}

func curl(namespace, address string) error {
	return runInNamespace(namespace, "curl", "--fail", "--silent", "--show-error", "--connect-timeout", "1", "--max-time", "1", address)
}

func runWithInput(namespace, input string, command ...string) error {
	arguments := append([]string{"netns", "exec", namespace}, command...)
	process := exec.Command("ip", arguments...)
	process.Stdin = strings.NewReader(input)
	output, err := process.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runInNamespace(namespace string, command ...string) error {
	arguments := append([]string{"ip", "netns", "exec", namespace}, command...)
	return run(arguments[0], arguments[1:]...)
}

func run(command string, arguments ...string) error {
	process := exec.Command(command, arguments...)
	output, err := process.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", command, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func commandOutput(t *testing.T, command string, arguments ...string) string {
	t.Helper()
	process := exec.Command(command, arguments...)
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v (%s)", command, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func commandOutputWithInput(t *testing.T, input, command string, arguments ...string) string {
	t.Helper()
	process := exec.Command(command, arguments...)
	process.Stdin = strings.NewReader(input)
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v (%s)", command, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output)
}
