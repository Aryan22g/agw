//go:build linux

package netns

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Available reports whether this host can build a sandbox.
func Available() bool {
	return run("ip", "-V") == nil && run("nft", "--version") == nil
}

// Create builds the namespace and applies enforcement.
//
// The ordering matters and is the opposite of what a minimal implementation
// would do. Routing, forwarding and NAT are all set up so that egress WOULD
// work, and only then is the firewall applied. A sandbox that cannot reach the
// internet because nothing was configured proves nothing; one that cannot
// reach it because of a rule we wrote is a control someone can audit, test,
// and watch fail open if they delete it.
func Create(cfg Config) (*Sandbox, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	addrs := cfg.Subnet.Addr()
	hostIP := addrs.Next()   // .1
	guestIP := hostIP.Next() // .2
	if !cfg.Subnet.Contains(guestIP) {
		return nil, fmt.Errorf("netns: subnet %s has no room for two addresses", cfg.Subnet)
	}

	s := &Sandbox{
		name:      "agw-" + cfg.Name,
		hostIface: "agwh-" + cfg.Name,
		peerIface: "agwp-" + cfg.Name,
		hostIP:    hostIP,
		guestIP:   guestIP,
		proxyPort: cfg.ProxyPort,
		table:     "agw_" + cfg.Name,
	}

	// Anything left over from an unclean shutdown would make this fail in
	// confusing ways.
	s.cleanupQuietly()

	steps := []struct {
		what string
		args []string
	}{
		{"create namespace", []string{"ip", "netns", "add", s.name}},
		{"create interface pair", []string{"ip", "link", "add", s.hostIface, "type", "veth", "peer", "name", s.peerIface}},
		{"move peer into namespace", []string{"ip", "link", "set", s.peerIface, "netns", s.name}},

		{"address the host side", []string{"ip", "addr", "add",
			netip.PrefixFrom(hostIP, cfg.Subnet.Bits()).String(), "dev", s.hostIface}},
		{"bring up the host side", []string{"ip", "link", "set", s.hostIface, "up"}},

		{"address the sandbox side", []string{"ip", "netns", "exec", s.name, "ip", "addr", "add",
			netip.PrefixFrom(guestIP, cfg.Subnet.Bits()).String(), "dev", s.peerIface}},
		{"bring up the sandbox side", []string{"ip", "netns", "exec", s.name, "ip", "link", "set", s.peerIface, "up"}},
		{"bring up sandbox loopback", []string{"ip", "netns", "exec", s.name, "ip", "link", "set", "lo", "up"}},

		// A default route, so the sandbox believes it has a way out and its
		// escape attempts are real attempts rather than immediate failures.
		{"give the sandbox a default route", []string{"ip", "netns", "exec", s.name,
			"ip", "route", "add", "default", "via", hostIP.String()}},

		// Forwarding and NAT: the path out genuinely works from here.
	}

	// Written directly rather than through sysctl(8), which a minimal image
	// may not ship.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		s.cleanupQuietly()
		return nil, fmt.Errorf("netns: enable forwarding: %w", err)
	}

	for _, step := range steps {
		if err := run(step.args[0], step.args[1:]...); err != nil {
			s.cleanupQuietly()
			return nil, fmt.Errorf("netns: %s: %w", step.what, err)
		}
	}

	// Turned off before the firewall goes up, so there is never a window in
	// which the stack is live and unfiltered.
	if !cfg.AllowIPv6 {
		s.ipv6Disabled = s.disableIPv6()
	}

	if err := s.applyRules(cfg.Subnet); err != nil {
		s.cleanupQuietly()
		return nil, err
	}

	return s, nil
}

// disableIPv6 turns the stack off inside the namespace and verifies it.
//
// Reported rather than enforced: a failure here is not a containment failure,
// because the filter table is `inet` and drops both families. Returning the
// real outcome means a caller can say which of the two situations it is in,
// instead of printing a claim it has not checked.
func (s *Sandbox) disableIPv6() bool {
	for _, knob := range []string{"all", "default"} {
		_ = run("ip", "netns", "exec", s.name, "sh", "-c",
			fmt.Sprintf("echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6", knob))
	}

	out, err := exec.Command("ip", "netns", "exec", s.name,
		"cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

// applyRules installs NAT and the firewall.
//
// The NAT rule is what makes this an honest demonstration: with it in place
// and the filter chain removed, the sandbox reaches the internet. The filter
// chain is therefore the control, and its absence is immediately visible as
// egress working.
//
// Refused packets are counted per category so WatchRefusals can put them in
// the evidence chain. See dropwatch.go for why counters rather than logs.
func (s *Sandbox) applyRules(subnet netip.Prefix) error {
	rules := strings.Join([]string{
		fmt.Sprintf("table inet %s {", s.table),

		// Named counters, one per category. These are the evidence: exact,
		// lossless, and readable from inside a container, which per-packet
		// kernel logging is not.
		fmt.Sprintf("  counter %s {}", counterMetadata),
		fmt.Sprintf("  counter %s {}", counterPrivate),
		fmt.Sprintf("  counter %s {}", counterOther),
		fmt.Sprintf("  counter %s {}", counterHostPort),

		// NAT, so egress would succeed and the filter below is demonstrably
		// the thing preventing it.
		"  chain postrouting {",
		"    type nat hook postrouting priority srcnat; policy accept;",
		fmt.Sprintf("    ip saddr %s oifname != \"%s\" masquerade", subnet, s.hostIface),
		"  }",

		// Traffic aimed past the host. Nothing is accepted: the sandbox's one
		// permitted destination is the proxy, which is on the host and so
		// arrives through input rather than forward.
		//
		// Each rule counts and drops in the same breath. Counting cannot be
		// rate limited or fall through -- if it could, the firewall would
		// leak under exactly the load that indicates an attack.
		"  chain forward {",
		"    type filter hook forward priority filter; policy accept;",
		fmt.Sprintf("    iifname \"%s\" ip daddr 169.254.0.0/16 counter name \"%s\" drop",
			s.hostIface, counterMetadata),
		fmt.Sprintf("    iifname \"%s\" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } "+
			"counter name \"%s\" drop", s.hostIface, counterPrivate),

		// IPv6. The catch-all below already DROPS v6 -- the table is inet, so
		// containment never depended on these rules. What they fix is the
		// category: without them an IPv6 probe for cloud credentials is
		// recorded as ordinary external traffic, which is the same
		// signal-quality bug that made an IPv4 metadata probe look like a
		// typo'd hostname.
		//
		// fd00:ec2::254 is AWS's IPv6 instance metadata address. It sits
		// inside fc00::/7, so it has to be matched before the ULA rule.
		fmt.Sprintf("    iifname \"%s\" ip6 daddr fd00:ec2::254 counter name \"%s\" drop",
			s.hostIface, counterMetadata),
		fmt.Sprintf("    iifname \"%s\" ip6 daddr fe80::/10 counter name \"%s\" drop",
			s.hostIface, counterMetadata),
		fmt.Sprintf("    iifname \"%s\" ip6 daddr fc00::/7 counter name \"%s\" drop",
			s.hostIface, counterPrivate),
		fmt.Sprintf("    iifname \"%s\" counter name \"%s\" drop", s.hostIface, counterOther),
		"  }",

		// Traffic aimed at the host itself. Only the proxy port.
		"  chain input {",
		"    type filter hook input priority filter; policy accept;",
		fmt.Sprintf("    iifname \"%s\" tcp dport %d accept", s.hostIface, s.proxyPort),
		fmt.Sprintf("    iifname \"%s\" ct state established,related accept", s.hostIface),
		// DNS to the host resolver would otherwise be both a reachable
		// service and an exfiltration channel. The proxy resolves on the
		// sandbox's behalf.
		fmt.Sprintf("    iifname \"%s\" counter name \"%s\" drop", s.hostIface, counterHostPort),
		"  }",
		"}",
	}, "\n")

	if err := runInput("nft", rules, "-f", "-"); err != nil {
		return fmt.Errorf("netns: apply firewall: %w", err)
	}
	return nil
}

// Command builds a command that will run inside the sandbox.
//
// `ip netns exec` is used rather than manipulating namespaces from Go. It is
// auditable -- an operator can run the same command by hand and see exactly
// what the workload sees -- and it avoids threading and fork-safety problems
// that come with setns in a Go runtime that multiplexes goroutines onto
// threads.
func (s *Sandbox) Command(ctx context.Context, argv ...string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("netns: no command given")
	}
	if s.destroyed {
		return nil, fmt.Errorf("netns: sandbox %s has been destroyed", s.name)
	}

	full := append([]string{"netns", "exec", s.name}, argv...)
	cmd := exec.CommandContext(ctx, "ip", full...)
	env := s.env
	if env == nil {
		env = MinimalEnv(os.Environ())
	}
	cmd.Env = append(append([]string{}, env...), ProxyEnv(s.ProxyAddr())...)
	return cmd, nil
}

// Destroy removes everything Create made.
func (s *Sandbox) Destroy() error {
	if s.destroyed {
		return nil
	}
	s.destroyed = true

	var firstErr error
	// The firewall goes first: if teardown fails halfway, the sandbox should
	// be left unable to reach anything rather than unexpectedly able to.
	if err := run("nft", "delete", "table", "inet", s.table); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := run("ip", "netns", "del", s.name); err != nil && firstErr == nil {
		firstErr = err
	}
	// Deleting the namespace takes the peer with it; the host side may
	// linger if the pair was created but never moved.
	_ = run("ip", "link", "del", s.hostIface)

	return firstErr
}

func (s *Sandbox) cleanupQuietly() {
	_ = run("nft", "delete", "table", "inet", s.table)
	_ = run("ip", "netns", "del", s.name)
	_ = run("ip", "link", "del", s.hostIface)
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runInput(name, stdin string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
