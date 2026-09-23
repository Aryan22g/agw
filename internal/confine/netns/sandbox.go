// Package netns builds the confinement boundary ourselves, rather than
// relying on a container runtime to do it.
//
// The Docker demo in demo/ uses an --internal network, which is a legitimate
// deployment but a weak proof: the containment is Docker's, and the honest
// reading is "we configured a runtime" rather than "we enforce".
//
// This package sets up the namespace, the interface pair, the routing, the
// NAT and the firewall directly. The important consequence is that egress
// would work: forwarding is on and traffic is masqueraded, so the only thing
// standing between the workload and the internet is a rule we wrote. Delete
// that rule and the workload gets out. That is a control, not an omission.
//
// KNOWN GAP: traffic the firewall drops does not reach the proxy, and so does
// not appear in the evidence chain. A workload probing 169.254.169.254
// directly is stopped, but silently -- only the attempts it routes through
// the proxy are recorded. That is the wrong way round: a direct probe of the
// metadata endpoint is a higher-signal event than one that politely used the
// proxy, and it is the one an incident responder most wants to see.
//
// Closing it means logging dropped packets (nftables `log` with a prefix,
// read from the kernel log or via nflog) and feeding those into the same
// chain. Until that exists, the evidence answers "what did the workload ask
// the proxy for", not "what did the workload attempt".
package netns

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrUnsupported is returned on platforms without network namespaces.
var ErrUnsupported = errors.New("netns: network namespaces are only available on Linux")

// Config describes a sandbox to build.
type Config struct {
	// Name identifies the namespace and the interfaces derived from it.
	// Kept short: interface names are capped at 15 characters.
	Name string

	// Subnet is the point-to-point link between host and sandbox. A /30 is
	// the whole allocation -- the sandbox gets exactly one address and has
	// no room to pretend to be anything else.
	Subnet netip.Prefix

	// ProxyPort is the only port the sandbox may reach on the host.
	ProxyPort int

	// AllowIPv6 leaves IPv6 enabled inside the sandbox.
	//
	// Default is off. Create assigns no global IPv6 address, so nothing
	// legitimate needs the stack -- but the kernel brings up a link-local
	// address regardless, and an address family that is enabled and not
	// needed is reachability nobody asked for. Containment does not depend on
	// this: the filter table is `inet` and its catch-all drop is
	// family-agnostic. Disabling it removes surface rather than adding
	// enforcement.
	AllowIPv6 bool
}

// Sandbox is a live network namespace with enforcement applied.
type Sandbox struct {
	name      string
	hostIface string
	peerIface string

	hostIP  netip.Addr
	guestIP netip.Addr

	proxyPort int
	table     string

	// ipv6Disabled records whether the stack was actually turned off, so a
	// caller can report it rather than assume it.
	ipv6Disabled bool

	destroyed bool

	// env is what the workload starts with, before the proxy variables.
	env []string
}

// IPv6Disabled reports whether IPv6 was turned off inside the sandbox.
func (s *Sandbox) IPv6Disabled() bool { return s.ipv6Disabled }

// HostIP is the address the proxy should listen on. It is inside the
// point-to-point link, not a wildcard bind, so the proxy is reachable from
// this sandbox and from nothing else.
func (s *Sandbox) HostIP() netip.Addr { return s.hostIP }

// GuestIP is the address the workload's traffic will arrive from. This is the
// binding that makes provenance identity work: the supervisor assigns it, the
// workload cannot choose it.
func (s *Sandbox) GuestIP() netip.Addr { return s.guestIP }

// Name returns the namespace name.
func (s *Sandbox) Name() string { return s.name }

// ProxyAddr is the host:port a workload inside the sandbox should use.
func (s *Sandbox) ProxyAddr() string {
	return fmt.Sprintf("%s:%d", s.hostIP, s.proxyPort)
}

func (c *Config) validate() error {
	if c.Name == "" {
		return errors.New("netns: name is required")
	}
	if len(c.Name) > 8 {
		// Interface names derive from this and are capped at 15 bytes.
		return fmt.Errorf("netns: name %q is too long (max 8)", c.Name)
	}
	if !c.Subnet.IsValid() || !c.Subnet.Addr().Is4() {
		return errors.New("netns: an IPv4 subnet is required")
	}
	if c.Subnet.Bits() < 24 {
		return fmt.Errorf("netns: subnet %s is wider than needed; a /30 is enough", c.Subnet)
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return fmt.Errorf("netns: proxy port %d out of range", c.ProxyPort)
	}
	return nil
}

// ProxyEnv is the environment that points a cooperating client at the proxy.
//
// Both spellings are set. curl reads only the lowercase http_proxy for plain
// HTTP -- the uppercase form is ignored there on purpose, because HTTP_PROXY
// can be set by a CGI request header -- while other tools read only the
// uppercase. With one spelling missing, a well-behaved agent's plain-HTTP
// request skipped the proxy and died at the firewall: still contained, but
// unattributed, and legitimate traffic to a permitted host failed.
//
// NO_PROXY is set empty for the same reason: an operator's NO_PROXY would
// otherwise send those destinations direct, where the firewall drops them.
func ProxyEnv(proxyAddr string) []string {
	u := "http://" + proxyAddr
	return []string{
		"AGW_PROXY=" + proxyAddr,
		"HTTP_PROXY=" + u, "http_proxy=" + u,
		"HTTPS_PROXY=" + u, "https_proxy=" + u,
		"ALL_PROXY=" + u, "all_proxy=" + u,
		"NO_PROXY=", "no_proxy=",
	}
}

// minimalEnvNames are the variables a workload gets by default: enough for a
// shell, a package manager and a language runtime to behave, and nothing that
// is plausibly a secret.
var minimalEnvNames = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ", "TMPDIR",
	"LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
}

// MinimalEnv returns the default workload environment, taken from the given
// environment (normally os.Environ()).
func MinimalEnv(from []string) []string {
	keep := make(map[string]bool, len(minimalEnvNames))
	for _, n := range minimalEnvNames {
		keep[n] = true
	}
	var out []string
	for _, kv := range from {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				if keep[kv[:i]] {
					out = append(out, kv)
				}
				break
			}
		}
	}
	return out
}

// SetEnv replaces the environment the workload starts with. The proxy
// variables are always added afterwards, so they cannot be overridden.
//
// Nothing is inherited by default. The supervisor's environment is the
// operator's -- cloud credentials, API tokens, the path to the checkpoint key
// -- and handing it to the workload is exactly the harvest in step 4a of the
// July 2026 Hugging Face intrusion. The caller decides what crosses.
func (s *Sandbox) SetEnv(env []string) { s.env = append([]string(nil), env...) }
