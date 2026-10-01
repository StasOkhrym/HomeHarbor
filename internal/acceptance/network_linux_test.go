//go:build linux && network_acceptance

package acceptance

import (
	"bufio"
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
			if strings.Contains(err.Error(), "Operation not permitted") ||
				strings.Contains(err.Error(), "Permission denied") {
				t.Fatalf("mandatory network namespace acceptance unavailable: %v", err)
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
	servers = append(servers, startTCPBannerServers(t, lanNS, 2222, 2223)...)
	waitForTCPBanner(t, clientNS, "192.168.50.2", 2222)
	waitForTCPBanner(t, clientNS, "192.168.50.2", 2223)

	peers := map[string]netip.Prefix{"client": netip.MustParsePrefix("100.64.0.2/32")}
	rules := policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{
		ID:             "allow-http",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       8080,
		PortTo:         8080,
	}, {
		ID:             "allow-ssh",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       2222,
		PortTo:         2222,
	}}}
	applyDefaultDenyPolicy(t, gatewayNS, "gt0", peers, rules)

	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	if err := curl(clientNS, "http://192.168.50.2:8081"); err == nil {
		t.Fatal("default-deny policy allowed a forbidden port")
	}
	if err := tcpBanner(clientNS, "192.168.50.2", 2223); err == nil {
		t.Fatal("default-deny policy allowed a forbidden SSH port")
	}
	verifyGatewayInputDenied(t, clientNS, gatewayNS)
	verifyUnrelatedForwarding(t, clientNS, gatewayNS, lanNS)
	verifyEstablishedRevoke(t, clientNS, gatewayNS, lanNS, "gt0", peers)
}

func TestLinuxNamespaceKernelWireGuardDefaultDenyLANAccess(t *testing.T) {
	requireNetworkTools(t, true)

	suffix := fmt.Sprintf("%d-wg", os.Getpid())
	clientNS := "gt-client-" + suffix
	gatewayNS := "gt-gateway-" + suffix
	lanNS := "gt-lan-" + suffix
	for _, namespace := range []string{clientNS, gatewayNS, lanNS} {
		if err := run("ip", "netns", "add", namespace); err != nil {
			if strings.Contains(err.Error(), "Operation not permitted") ||
				strings.Contains(err.Error(), "Permission denied") {
				t.Fatalf("mandatory network namespace acceptance unavailable: %v", err)
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
	// Bootstrap default-deny BEFORE bringing up the encrypted interface.
	// With no ACL even a valid WireGuard handshake conveys no LAN authority.
	applyDefaultDenyPolicy(
		t,
		gatewayNS,
		"wg0",
		nil,
		policy.Snapshot{DefaultAction: policy.ActionDeny},
	)
	configureWireGuard(t, clientNS, gatewayNS)
	if err := runInNamespace(
		lanNS,
		"ip",
		"route",
		"replace",
		"10.200.0.0/24",
		"via",
		"192.168.50.1",
	); err != nil {
		t.Fatal(err)
	}
	servers := startHTTPServers(t, lanNS)
	servers = append(servers, startTCPBannerServers(t, lanNS, 2222, 2223)...)
	t.Cleanup(func() {
		for _, server := range servers {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	})

	if err := curl(clientNS, "http://192.168.50.2:8080"); err == nil {
		t.Fatal("boot guard allowed encrypted LAN access before policy")
	}
	peers := map[string]netip.Prefix{"client": netip.MustParsePrefix("10.200.0.2/32")}
	rules := policy.Snapshot{Revision: 1, DefaultAction: policy.ActionDeny, Rules: []policy.Rule{{
		ID:             "allow-http",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       8080,
		PortTo:         8080,
	}, {
		ID:             "allow-ssh",
		SourceDeviceID: "client",
		Destination:    netip.MustParsePrefix("192.168.50.2/32"),
		Protocol:       policy.ProtocolTCP,
		PortFrom:       2222,
		PortTo:         2222,
	}}}
	applyDefaultDenyPolicy(t, gatewayNS, "wg0", peers, rules)

	waitForHTTP(t, clientNS, "http://192.168.50.2:8080")
	if err := curl(clientNS, "http://192.168.50.2:8081"); err == nil {
		t.Fatal("default-deny policy allowed a forbidden WireGuard port")
	}
	if err := tcpBanner(clientNS, "192.168.50.2", 2223); err == nil {
		t.Fatal("default-deny policy allowed a forbidden WireGuard SSH port")
	}
	verifyUnrelatedForwarding(t, clientNS, gatewayNS, lanNS)
	verifyEstablishedRevoke(t, clientNS, gatewayNS, lanNS, "wg0", peers)
}

func requireNetworkTools(t *testing.T, wireGuard bool) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Fatal("mandatory network namespace acceptance requires root or CAP_NET_ADMIN")
	}

	commands := []string{"ip", "nft", "curl", "python3"}
	if wireGuard {
		commands = append(commands, "wg")
	}

	for _, command := range commands {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatalf("mandatory network namespace acceptance requires %s: %v", command, err)
		}
	}
}

func applyDefaultDenyPolicy(
	t *testing.T,
	namespace, interfaceName string,
	peers map[string]netip.Prefix,
	rules policy.Snapshot,
) {
	t.Helper()
	script, err := nft.Compile(interfaceName, peers, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := runInNamespace(namespace, "nft", "list", "table", "inet", "go_tunnels"); err == nil {
		script = "flush table inet go_tunnels\n" + script
	}
	if err := runWithInput(namespace, script, "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
}

func verifyGatewayInputDenied(t *testing.T, clientNS, gatewayNS string) {
	t.Helper()
	server := exec.Command(
		"ip",
		"netns",
		"exec",
		gatewayNS,
		"python3",
		"-m",
		"http.server",
		"8082",
		"--bind",
		"100.64.0.1",
	)
	server.Stdout, server.Stderr = io.Discard, io.Discard

	if err := server.Start(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	waitForHTTP(t, gatewayNS, "http://100.64.0.1:8082")

	if err := curl(clientNS, "http://100.64.0.1:8082"); err == nil {
		t.Fatal("tunnel accessed a gateway-local service without input authorization")
	}
}

func verifyUnrelatedForwarding(t *testing.T, clientNS, gatewayNS, lanNS string) {
	t.Helper()
	for _, command := range [][]string{
		{"ip", "link", "add", "gt-other-peer", "type", "veth", "peer", "name", "other0"},
		{"ip", "link", "set", "gt-other-peer", "netns", clientNS},
		{"ip", "link", "set", "other0", "netns", gatewayNS},
	} {
		if err := run(command[0], command[1:]...); err != nil {
			t.Fatal(err)
		}
	}

	for _, command := range [][]string{
		{clientNS, "ip", "addr", "add", "172.20.0.2/24", "dev", "gt-other-peer"},
		{gatewayNS, "ip", "addr", "add", "172.20.0.1/24", "dev", "other0"},
		{clientNS, "ip", "link", "set", "gt-other-peer", "up"},
		{gatewayNS, "ip", "link", "set", "other0", "up"},
		{clientNS, "ip", "rule", "add", "from", "172.20.0.2", "table", "100"},
		{clientNS, "ip", "route", "add", "192.168.50.0/24", "via", "172.20.0.1", "dev", "gt-other-peer", "table", "100"},
		{lanNS, "ip", "route", "add", "172.20.0.0/24", "via", "192.168.50.1"},
	} {
		if err := runInNamespace(command[0], command[1:]...); err != nil {
			t.Fatal(err)
		}
	}

	if err := runInNamespace(
		clientNS,
		"curl",
		"--interface",
		"172.20.0.2",
		"--fail",
		"--silent",
		"--max-time",
		"2",
		"http://192.168.50.2:8081",
	); err != nil {
		t.Fatalf("tunnel firewall blocked unrelated forwarding: %v", err)
	}
}

// Keep one real TCP connection through a policy update: new-connection curl
// assertions alone cannot detect an established/related acceptance bypass.
func verifyEstablishedRevoke(
	t *testing.T,
	clientNS, gatewayNS, lanNS, link string,
	peers map[string]netip.Prefix,
) {
	t.Helper()
	const echo = `import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("192.168.50.2",9090));s.listen()
def echo(c):
 with c:
  while True:
   data=c.recv(128)
   if not data: break
   c.sendall(data)
while True:
 c,_=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()`
	server := exec.Command("ip", "netns", "exec", lanNS, "python3", "-u", "-c", echo)
	server.Stdout, server.Stderr = io.Discard, io.Discard
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	allow := policy.Snapshot{
		Revision:      2,
		DefaultAction: policy.ActionDeny,
		Rules: []policy.Rule{
			{
				ID:             "echo",
				SourceDeviceID: "client",
				Destination:    netip.MustParsePrefix("192.168.50.2/32"),
				Protocol:       policy.ProtocolTCP,
				PortFrom:       9090,
				PortTo:         9090,
			},
		},
	}
	applyDefaultDenyPolicy(t, gatewayNS, link, peers, allow)
	const client = `import socket,sys,time
deadline=time.monotonic()+5
while True:
 try: s=socket.create_connection(("192.168.50.2",9090),timeout=1);break
 except OSError:
  if time.monotonic()>deadline: raise
  time.sleep(.1)
with s:
 s.sendall(b"first");assert s.recv(128)==b"first"
 print("ESTABLISHED",flush=True)
 sys.stdin.readline()
 s.sendall(b"revoked")
 try:
  data=s.recv(128)
  print("BYPASS" if data else "BLOCKED",flush=True)
 except (TimeoutError,OSError): print("BLOCKED",flush=True)`
	process := exec.Command("ip", "netns", "exec", clientNS, "python3", "-u", "-c", client)
	input, err := process.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	process.Stderr = io.Discard
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close(); _ = process.Process.Kill(); _ = process.Wait() })
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "ESTABLISHED" {
		t.Fatal("could not establish authorized TCP flow")
	}
	allow.Revision, allow.Rules = 3, nil
	applyDefaultDenyPolicy(t, gatewayNS, link, peers, allow)
	if _, err := io.WriteString(input, "revoke\n"); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() || scanner.Text() != "BLOCKED" {
		t.Fatalf("established TCP flow survived ACL revoke: %q", scanner.Text())
	}
	// Empty ACL and the staged guard must both preserve unrelated forwarding.
	if err := runInNamespace(
		clientNS,
		"curl",
		"--interface",
		"172.20.0.2",
		"--fail",
		"--silent",
		"--max-time",
		"2",
		"http://192.168.50.2:8081",
	); err != nil {
		t.Fatalf("revocation blocked unrelated forwarding: %v", err)
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

	if err := runWithInput(
		gatewayNS,
		gatewayPrivate+"\n",
		"wg",
		"set",
		"wg0",
		"private-key",
		"/dev/stdin",
		"listen-port",
		"51820",
		"peer",
		clientPublic,
		"allowed-ips",
		"10.200.0.2/32",
		"endpoint",
		"100.64.0.2:51820",
		"persistent-keepalive",
		"25",
	); err != nil {
		t.Fatal(err)
	}

	if err := runWithInput(
		clientNS,
		clientPrivate+"\n",
		"wg",
		"set",
		"wg0",
		"private-key",
		"/dev/stdin",
		"listen-port",
		"51820",
		"peer",
		gatewayPublic,
		"allowed-ips",
		"192.168.50.0/24",
		"endpoint",
		"100.64.0.1:51820",
		"persistent-keepalive",
		"25",
	); err != nil {
		t.Fatal(err)
	}

	if err := runInNamespace(
		gatewayNS,
		"ip",
		"route",
		"add",
		"10.200.0.2/32",
		"dev",
		"wg0",
	); err != nil {
		t.Fatal(err)
	}

	if err := runInNamespace(
		clientNS,
		"ip",
		"route",
		"add",
		"192.168.50.0/24",
		"dev",
		"wg0",
	); err != nil {
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

	if err := run(
		"ip",
		"link",
		"add",
		"gt-client-peer",
		"type",
		"veth",
		"peer",
		"name",
		"gt0",
	); err != nil {
		t.Fatal(err)
	}

	if err := run("ip", "link", "set", "gt-client-peer", "netns", clientNS); err != nil {
		t.Fatal(err)
	}

	if err := run("ip", "link", "set", "gt0", "netns", gatewayNS); err != nil {
		t.Fatal(err)
	}

	if err := run(
		"ip",
		"link",
		"add",
		"gt-lan-peer",
		"type",
		"veth",
		"peer",
		"name",
		"lan0",
	); err != nil {
		t.Fatal(err)
	}

	if err := run("ip", "link", "set", "gt-lan-peer", "netns", gatewayNS); err != nil {
		t.Fatal(err)
	}

	if err := run("ip", "link", "set", "lan0", "netns", lanNS); err != nil {
		t.Fatal(err)
	}
}

func configureTopology(
	t *testing.T,
	clientNS, gatewayNS, lanNS string,
	routeLANViaOuterNetwork bool,
) {
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
		commands = append(
			commands,
			[]string{clientNS, "ip", "route", "add", "192.168.50.0/24", "via", "100.64.0.1"},
		)
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
		server := exec.Command(
			"ip",
			"netns",
			"exec",
			namespace,
			"python3",
			"-m",
			"http.server",
			port,
			"--bind",
			"192.168.50.2",
		)
		server.Stdout = io.Discard
		server.Stderr = io.Discard

		if err := server.Start(); err != nil {
			t.Fatal(err)
		}

		servers = append(servers, server)
	}

	return servers
}

func startTCPBannerServers(t *testing.T, namespace string, ports ...int) []*exec.Cmd {
	t.Helper()
	const serverScript = `import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2])))
s.listen(16)
while True:
 c,_=s.accept()
 try: c.sendall(b"SSH-2.0-GoTunnels-Test\\r\\n")
 finally: c.close()`
	servers := make([]*exec.Cmd, 0, len(ports))
	for _, port := range ports {
		server := exec.Command(
			"ip",
			"netns",
			"exec",
			namespace,
			"python3",
			"-c",
			serverScript,
			"192.168.50.2",
			fmt.Sprint(port),
		)
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
	var lastError error
	for time.Now().Before(deadline) {
		lastError = curl(namespace, address)
		if lastError == nil {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("HTTP service %s was not reachable: %v", address, lastError)
}

func curl(namespace, address string) error {
	return runInNamespace(
		namespace,
		"curl",
		"--fail",
		"--silent",
		"--show-error",
		"--connect-timeout",
		"1",
		"--max-time",
		"1",
		address,
	)
}

func waitForTCPBanner(t *testing.T, namespace, address string, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var lastError error
	for time.Now().Before(deadline) {
		lastError = tcpBanner(namespace, address, port)
		if lastError == nil {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("SSH-like service %s:%d was not reachable: %v", address, port, lastError)
}

func tcpBanner(namespace, address string, port int) error {
	const clientScript = `import socket,sys
with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1) as s:
 data=s.recv(64)
if not data.startswith(b"SSH-2.0-"): raise SystemExit(1)`
	return runInNamespace(namespace, "python3", "-c", clientScript, address, fmt.Sprint(port))
}

func runWithInput(namespace, input string, command ...string) error {
	arguments := append([]string{"netns", "exec", namespace}, command...)

	process := exec.Command("ip", arguments...)
	process.Stdin = strings.NewReader(input)

	output, err := process.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"ip %s: %w (%s)",
			strings.Join(arguments, " "),
			err,
			strings.TrimSpace(string(output)),
		)
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
		return fmt.Errorf(
			"%s %s: %w (%s)",
			command,
			strings.Join(arguments, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return nil
}

func commandOutput(t *testing.T, command string, arguments ...string) string {
	t.Helper()
	process := exec.Command(command, arguments...)

	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"%s %s: %v (%s)",
			command,
			strings.Join(arguments, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return string(output)
}

func commandOutputWithInput(t *testing.T, input, command string, arguments ...string) string {
	t.Helper()
	process := exec.Command(command, arguments...)
	process.Stdin = strings.NewReader(input)

	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf(
			"%s %s: %v (%s)",
			command,
			strings.Join(arguments, " "),
			err,
			strings.TrimSpace(string(output)),
		)
	}

	return string(output)
}
