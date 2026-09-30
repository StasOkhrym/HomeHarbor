//go:build linux

package acceptance

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/sokhrym/go-tunnels/internal/agent/dns"
)

// VM harness contract: run as root in a disposable Linux VM with the REAL
// systemd-resolved service, ip, resolvectl and python3. Namespace-only Docker
// cannot substitute for the VM's resolver/D-Bus ownership. Parent runner must
// include ^TestLinuxResolved in addition to ^TestLinuxNamespace. Missing
// prerequisites fail; portable unit tests live in internal/agent/dns instead.
func TestLinuxResolvedSplitDNSLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("resolved acceptance requires root in a disposable Linux VM")
	}
	for _, name := range []string{"ip", "resolvectl", "systemctl", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("resolved VM harness requires %s: %v", name, err)
		}
	}
	if err := run("systemctl", "is-active", "--quiet", "systemd-resolved"); err != nil {
		t.Fatalf("real systemd-resolved must be running: %v", err)
	}
	ctx := context.Background()
	link := "gt-resolved"
	namespace := fmt.Sprintf("gt-resolved-%d", os.Getpid())
	beforeDNS := commandOutput(t, "resolvectl", "dns")
	beforeDomains := commandOutput(t, "resolvectl", "domain")
	if err := run("ip", "netns", "add", namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = run("ip", "link", "del", link); _ = run("ip", "netns", "del", namespace) })
	for _, command := range [][]string{
		{"ip", "link", "add", link, "type", "veth", "peer", "name", "gt-dns-peer"},
		{"ip", "link", "set", "gt-dns-peer", "netns", namespace},
		{"ip", "addr", "add", "192.0.2.1/30", "dev", link},
		{"ip", "link", "set", link, "up"},
	} {
		if err := run(command[0], command[1:]...); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range [][]string{
		{"ip", "addr", "add", "192.0.2.2/30", "dev", "gt-dns-peer"},
		{"ip", "link", "set", "gt-dns-peer", "up"},
		{"ip", "link", "set", "lo", "up"},
	} {
		if err := runInNamespace(namespace, command...); err != nil {
			t.Fatal(err)
		}
	}
	// A real UDP DNS fixture gives every A query a reserved documentation
	// address. Assert queries for BOTH suffixes: resolved's domain command
	// replaces its list, so issuing one command per suffix loses the first.
	const serverScript = `import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("192.0.2.2",53))
print("READY",flush=True)
while True:
 data,addr=s.recvfrom(4096)
 end=12
 while data[end]: end+=data[end]+1
 end+=1
 qtype=struct.unpack("!H",data[end:end+2])[0]
 question=data[12:end+4]
 answer=b"\xc0\x0c"+struct.pack("!HHIH",1,1,0,4)+socket.inet_aton("198.51.100.42") if qtype==1 else b""
 header=data[:2]+struct.pack("!HHHHH",0x8180,1,1 if answer else 0,0,0)
 s.sendto(header+question+answer,addr)`
	server := exec.Command("ip", "netns", "exec", namespace, "python3", "-u", "-c", serverScript)
	output, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = io.Discard
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "READY" {
		t.Fatal("DNS fixture failed to bind")
	}
	manager, err := dns.NewManager(link)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close(ctx) })
	if err := manager.Apply(ctx, netip.MustParseAddr("192.0.2.2"), []string{"one.gt-test.arpa", "two.gt-test.arpa"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"host.one.gt-test.arpa", "host.two.gt-test.arpa"} {
		answer := commandOutput(t, "resolvectl", "query", "--type=A", name)
		if !strings.Contains(answer, "198.51.100.42") {
			t.Fatalf("private suffix %s did not use the managed resolver: %s", name, answer)
		}
	}
	if answer := commandOutput(t, "resolvectl", "default-route", link); !strings.Contains(answer, "no") {
		t.Fatalf("private resolver became a default route: %s", answer)
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if output := commandOutput(t, "resolvectl", "dns", link); strings.Contains(output, "192.0.2.2") {
		t.Fatalf("Close retained private resolver: %s", output)
	}
	if output := commandOutput(t, "resolvectl", "domain", link); strings.Contains(output, "gt-test.arpa") {
		t.Fatalf("Close retained private suffixes: %s", output)
	}
	if err := run("ip", "link", "del", link); err != nil {
		t.Fatal(err)
	}
	// Compare the host's actual resolver routing outside the owned link.
	// This is an observed VM lifecycle check, never a command-double claim.
	if after := commandOutput(t, "resolvectl", "dns"); after != beforeDNS {
		t.Fatalf("host DNS changed outside managed link: before=%s after=%s", beforeDNS, after)
	}
	if after := commandOutput(t, "resolvectl", "domain"); after != beforeDomains {
		t.Fatalf("host DNS domains changed outside managed link: before=%s after=%s", beforeDomains, after)
	}
}
