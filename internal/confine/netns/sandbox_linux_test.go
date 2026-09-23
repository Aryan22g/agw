//go:build linux

package netns_test

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Aryan22g/agw/internal/confine/netns"
)

func requireCapable(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to create network namespaces")
	}
	if !netns.Available() {
		t.Skip("needs the ip and nft binaries")
	}
}

func newSandbox(t *testing.T, name string, proxyPort int) *netns.Sandbox {
	t.Helper()
	sb, err := netns.Create(netns.Config{
		Name:      name,
		Subnet:    netip.MustParsePrefix("10.77.0.0/30"),
		ProxyPort: proxyPort,
	})
	if err != nil {
		t.Fatalf("create sandbox: %v", err)
	}
	t.Cleanup(func() { _ = sb.Destroy() })
	return sb
}

// inSandbox runs a command inside the namespace and reports success plus output.
func inSandbox(t *testing.T, sb *netns.Sandbox, timeout time.Duration, argv ...string) (bool, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd, err := sb.Command(ctx, argv...)
	if err != nil {
		t.Fatalf("build command: %v", err)
	}
	out, err := cmd.CombinedOutput()
	return err == nil, strings.TrimSpace(string(out))
}

// TestTheFirewallIsTheControl is the test that makes the claim honest.
//
// It is easy to build a sandbox that cannot reach the internet by simply not
// configuring a route, and call that containment. This proves the opposite:
// routing, forwarding and NAT are all in place, so egress works the moment
// our filter rule is removed. The rule is the control.
func TestTheFirewallIsTheControl(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "ctl", 18080)

	// 1. Contained: the sandbox cannot reach a public address.
	ok, out := inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/1.1.1.1/443")
	if ok {
		t.Fatalf("the sandbox reached the internet while the rule was in place: %s", out)
	}

	// 2. Remove OUR rule -- nothing else -- and egress must start working.
	//    If it does not, the containment above was an accident of missing
	//    configuration rather than an enforcement decision, and this whole
	//    package would be overclaiming.
	if err := exec.Command("nft", "flush", "chain", "inet", "agw_ctl", "forward").Run(); err != nil {
		t.Fatalf("flush our forward chain: %v", err)
	}

	ok, out = inSandbox(t, sb, 10*time.Second,
		"timeout", "6", "bash", "-c", "echo > /dev/tcp/1.1.1.1/443")
	if !ok {
		// A host can drop forwarded traffic for reasons of its own -- Docker
		// sets the iptables FORWARD policy to DROP, and so do ufw and
		// firewalld. Containment is then enforced twice, and this host cannot
		// show that our rule alone is sufficient. Say so, rather than report
		// that containment is not enforced. (CI resets that policy, and fails
		// on any skipped containment test, so the claim is still proven there.)
		if chains := foreignForwardDrops(t, "agw_ctl"); len(chains) > 0 {
			t.Skipf("another firewall on this host also drops forwarded traffic (%s), so this "+
				"host cannot show that our rule alone is the control. To run this test, "+
				"accept forwarding in those chains first, e.g. `iptables -P FORWARD ACCEPT`.",
				strings.Join(chains, ", "))
		}
		t.Fatalf("egress did not work even with our rule removed, so the rule was not what "+
			"was blocking it. Containment here is not being enforced: %s", out)
	}
	t.Log("confirmed: removing our forward rule restores egress, so the rule is the control")
}

// foreignForwardDrops names the forward-hook base chains, outside our own
// table, whose policy is drop.
func foreignForwardDrops(t *testing.T, ours string) []string {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return nil
	}
	var found []string
	var table, chain string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 3 && f[0] == "table":
			table = f[1] + " " + f[2]
		case len(f) >= 2 && f[0] == "chain":
			chain = f[1]
		case strings.Contains(line, "hook forward") && strings.Contains(line, "policy drop") &&
			!strings.HasSuffix(table, " "+ours):
			found = append(found, table+" "+chain)
		}
	}
	return found
}

// TestSandboxReachesOnlyTheProxyPort covers the permitted path.
func TestSandboxReachesOnlyTheProxyPort(t *testing.T) {
	requireCapable(t)

	// A listener on the host side of the link stands in for the proxy.
	ln, err := net.Listen("tcp", "10.77.0.1:18081")
	if err != nil {
		// The address only exists once the sandbox is created, so create
		// first and bind after.
		ln = nil
	}
	if ln != nil {
		_ = ln.Close()
	}

	sb := newSandbox(t, "port", 18081)

	ln, err = net.Listen("tcp", sb.HostIP().String()+":18081")
	if err != nil {
		t.Fatalf("listen on the host side: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ok, out := inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/"+sb.HostIP().String()+"/18081")
	if !ok {
		t.Errorf("the sandbox could not reach the proxy port: %s", out)
	}

	// Any other port on the host is refused.
	ok, out = inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/"+sb.HostIP().String()+"/18082")
	if ok {
		t.Errorf("the sandbox reached a host port that is not the proxy: %s", out)
	}
}

// TestMetadataEndpointIsUnreachable is the specific address that mattered in
// the July 2026 Hugging Face intrusion.
func TestMetadataEndpointIsUnreachable(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "meta", 18083)

	ok, out := inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/169.254.169.254/80")
	if ok {
		t.Errorf("the sandbox reached the metadata endpoint: %s", out)
	}
}

// TestRootInsideCannotRemoveTheRules is the trust-domain property.
//
// A process with root and CAP_NET_ADMIN inside the namespace can edit that
// namespace's own firewall all it likes. Our rules are in the host namespace,
// which it has no handle on.
func TestRootInsideCannotRemoveTheRules(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "esc", 18084)

	// Confirm root inside really is root and really does have nft.
	ok, out := inSandbox(t, sb, 8*time.Second, "id", "-u")
	if !ok || strings.TrimSpace(out) != "0" {
		t.Skipf("expected root inside the namespace, got %q (%v)", out, ok)
	}

	// From inside, our host-side table is not even visible.
	_, out = inSandbox(t, sb, 8*time.Second, "nft", "list", "ruleset")
	if strings.Contains(out, "agw_esc") {
		t.Errorf("the host firewall table is visible from inside the sandbox:\n%s", out)
	}

	// Attempting to delete it fails.
	ok, out = inSandbox(t, sb, 8*time.Second, "nft", "delete", "table", "inet", "agw_esc")
	if ok {
		t.Errorf("a process inside the sandbox deleted the host's firewall table: %s", out)
	}

	// And egress is still blocked afterwards.
	ok, out = inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/1.1.1.1/443")
	if ok {
		t.Errorf("egress worked after the escape attempt: %s", out)
	}
}

func TestDestroyIsCleanAndRepeatable(t *testing.T) {
	requireCapable(t)

	sb, err := netns.Create(netns.Config{
		Name:      "tidy",
		Subnet:    netip.MustParsePrefix("10.77.0.0/30"),
		ProxyPort: 18085,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := sb.Destroy(); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if err := sb.Destroy(); err != nil {
		t.Errorf("second destroy should be a no-op, got %v", err)
	}

	out, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(out), "agw-tidy") {
		t.Errorf("the namespace survived destroy:\n%s", out)
	}
	out, _ = exec.Command("nft", "list", "ruleset").CombinedOutput()
	if strings.Contains(string(out), "agw_tidy") {
		t.Errorf("the firewall table survived destroy:\n%s", out)
	}

	// Creating the same name again must work, so a crashed run does not
	// wedge the host.
	sb2, err := netns.Create(netns.Config{
		Name:      "tidy",
		Subnet:    netip.MustParsePrefix("10.77.0.0/30"),
		ProxyPort: 18085,
	})
	if err != nil {
		t.Fatalf("recreate after destroy: %v", err)
	}
	_ = sb2.Destroy()
}

// TestRefusedPacketsAreObservable closes the gap that made the evidence
// answer the wrong question.
//
// Before this, a workload probing 169.254.169.254 directly was stopped by the
// firewall and never reached the proxy, so nothing was recorded. The chain
// described what the workload asked the proxy for, not what it attempted --
// and a direct probe is the higher-signal event, because it means the
// workload decided not to talk to us.
func TestRefusedPacketsAreObservable(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "drops", 18090)

	before, err := sb.Refusals()
	if err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if before.Total() != 0 {
		t.Fatalf("a fresh sandbox already has %d refusals", before.Total())
	}

	// Three attempts, three categories.
	_, _ = inSandbox(t, sb, 8*time.Second,
		"timeout", "4", "bash", "-c", "echo > /dev/tcp/169.254.169.254/80")
	_, _ = inSandbox(t, sb, 8*time.Second,
		"timeout", "4", "bash", "-c", "echo > /dev/tcp/192.168.5.5/22")
	_, _ = inSandbox(t, sb, 8*time.Second,
		"timeout", "4", "bash", "-c", "echo > /dev/tcp/1.1.1.1/443")

	after, err := sb.Refusals()
	if err != nil {
		t.Fatalf("read counters: %v", err)
	}
	t.Logf("refusals: metadata=%d private=%d external=%d host=%d",
		after.Metadata, after.Private, after.Other, after.HostPort)

	if after.Metadata == 0 {
		t.Error("a direct probe of the metadata endpoint was not recorded; " +
			"the evidence would not show it was attempted")
	}
	if after.Private == 0 {
		t.Error("an internal pivot attempt was not recorded")
	}
	if after.Other == 0 {
		t.Error("an attempt to reach the public internet was not recorded")
	}
}

// TestWatchRefusalsReportsDeltas covers the streaming path agw run uses.
func TestWatchRefusalsReportsDeltas(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "watch", 18092)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	seen := make(chan netns.Refusal, 32)
	go func() {
		_ = sb.WatchRefusals(ctx, 500*time.Millisecond, func(r netns.Refusal) {
			select {
			case seen <- r:
			default:
			}
		})
	}()
	time.Sleep(700 * time.Millisecond)

	_, _ = inSandbox(t, sb, 8*time.Second,
		"timeout", "4", "bash", "-c", "echo > /dev/tcp/169.254.169.254/80")

	deadline := time.After(12 * time.Second)
	for {
		select {
		case r := <-seen:
			if r.Category == netns.CategoryMetadata {
				if r.Delta == 0 {
					t.Error("a refusal was reported with a zero delta")
				}
				t.Logf("observed %s delta=%d total=%d", r.Category, r.Delta, r.Total)
				return
			}
		case <-deadline:
			t.Fatal("no metadata refusal was reported by the watcher")
		}
	}
}

// TestCountAndDropAreTheSameRule guards a mistake that would make the
// firewall leak under exactly the load that indicates an attack.
//
// If counting and dropping were separate rules, or if a rate limit sat on the
// drop, packets above the limit would fall through to the chain policy --
// which is accept.
func TestCountAndDropAreTheSameRule(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "nolim", 18091)

	out, err := exec.Command("nft", "list", "table", "inet", "agw_nolim").CombinedOutput()
	if err != nil {
		t.Fatalf("list ruleset: %v: %s", err, out)
	}

	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "counter name") {
			continue
		}
		if !strings.HasSuffix(trimmed, "drop") {
			t.Errorf("a counting rule does not also drop, so traffic falls through:\n  %s", trimmed)
		}
		if strings.Contains(trimmed, "limit") {
			t.Errorf("a drop rule carries a rate limit, so the firewall leaks above it:\n  %s", trimmed)
		}
	}

	// And the sandbox stays contained at volume.
	ok, _ := inSandbox(t, sb, 20*time.Second, "bash", "-c",
		"for i in $(seq 1 40); do timeout 1 bash -c 'echo > /dev/tcp/1.1.1.1/443' 2>/dev/null && exit 0; done; exit 1")
	if ok {
		t.Error("one of 40 rapid connection attempts got out")
	}

	counts, err := sb.Refusals()
	if err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if counts.Other == 0 {
		t.Error("40 refused attempts produced no counter increase")
	}
	t.Logf("refused %d external packets", counts.Other)
}

// TestIPv6IsOffByDefault. The kernel brings up a link-local IPv6 address on
// the veth whether or not anything needs it. Create assigns no global IPv6
// address, so nothing legitimate does.
//
// Containment never depended on this -- the filter table is `inet` and its
// catch-all drop is family-agnostic, which TestIPv6IsStillContained below
// checks directly. Disabling the stack removes reachability nobody asked for.
func TestIPv6IsOffByDefault(t *testing.T) {
	requireCapable(t)
	sb := newSandbox(t, "no6", 18093)

	if !sb.IPv6Disabled() {
		t.Error("IPv6 was left enabled in the sandbox")
	}

	ok, out := inSandbox(t, sb, 8*time.Second, "cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if !ok {
		t.Skipf("could not read the sysctl: %s", out)
	}
	if strings.TrimSpace(out) != "1" {
		t.Errorf("disable_ipv6 = %q, want 1", strings.TrimSpace(out))
	}
}

// TestIPv6IsStillContainedWhenEnabled is the more important half: an operator
// who turns IPv6 on must not lose containment.
func TestIPv6IsStillContainedWhenEnabled(t *testing.T) {
	requireCapable(t)

	sb, err := netns.Create(netns.Config{
		Name:      "with6",
		Subnet:    netip.MustParsePrefix("10.77.0.0/30"),
		ProxyPort: 18094,
		AllowIPv6: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = sb.Destroy() })

	if sb.IPv6Disabled() {
		t.Fatal("AllowIPv6 was set but the stack was disabled anyway")
	}

	// Public IPv6, via the catch-all drop rather than any v6-specific rule.
	ok, out := inSandbox(t, sb, 8*time.Second,
		"timeout", "5", "bash", "-c", "echo > /dev/tcp/2606:4700::1111/443")
	if ok {
		t.Errorf("the sandbox reached a public IPv6 address: %s", out)
	}
}

// TestIPv6RulesArePresentForCategorisation.
//
// The v4 rules classify a refusal as metadata, private or external. Without
// the v6 equivalents an IPv6 probe for cloud credentials -- AWS serves
// instance metadata at fd00:ec2::254 -- is still dropped, but recorded as
// ordinary external traffic. That is the same signal-quality bug that once
// made an IPv4 metadata probe look like a typo'd hostname.
func TestIPv6RulesArePresentForCategorisation(t *testing.T) {
	requireCapable(t)
	_ = newSandbox(t, "cat6", 18095)

	out, err := exec.Command("nft", "list", "table", "inet", "agw_cat6").CombinedOutput()
	if err != nil {
		t.Fatalf("list ruleset: %v: %s", err, out)
	}
	ruleset := string(out)

	for _, want := range []string{"fd00:ec2::254", "fe80::/10", "fc00::/7"} {
		if !strings.Contains(ruleset, want) {
			t.Errorf("no rule covers %s, so an IPv6 refusal there is mis-categorised:\n%s",
				want, ruleset)
		}
	}
}

// TestHostSecretsDoNotReachTheWorkload: the supervisor's environment is the
// operator's, and nothing in it crosses unless the caller says so.
func TestHostSecretsDoNotReachTheWorkload(t *testing.T) {
	requireCapable(t)
	t.Setenv("AWS_SECRET_ACCESS_KEY", "host-secret-must-not-cross")
	t.Setenv("NO_PROXY", "pypi.org")

	sb := newSandbox(t, "agwenv", 18089)
	ok, out := inSandbox(t, sb, 5*time.Second, "sh", "-c", "env")
	if !ok {
		t.Fatalf("env failed: %s", out)
	}
	if strings.Contains(out, "host-secret-must-not-cross") {
		t.Fatal("a host credential was visible inside the sandbox")
	}
	for _, want := range []string{"http_proxy=http://", "HTTP_PROXY=http://", "https_proxy=http://", "PATH="} {
		if !strings.Contains(out, want) {
			t.Errorf("workload environment lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "NO_PROXY=pypi.org") {
		t.Error("the operator's NO_PROXY leaked in; those hosts would bypass the proxy")
	}

	// An explicit grant does cross.
	sb.SetEnv(append(netns.MinimalEnv(os.Environ()), "MODEL_API_KEY=granted"))
	_, out = inSandbox(t, sb, 5*time.Second, "sh", "-c", "echo $MODEL_API_KEY")
	if out != "granted" {
		t.Errorf("an explicitly granted variable did not arrive: %q", out)
	}
}
