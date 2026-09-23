// Package sidecar confines a workload that shares a network namespace with
// the enforcement point: a Kubernetes pod, or containers joined with
// `docker run --network container:NAME`.
//
// The netns substrate (`agw run`) gives the workload a namespace of its own
// with the proxy outside it. Where the platform owns the namespace -- every
// Kubernetes pod -- that is not available, and the pattern the industry
// settled on (Istio, Linkerd) is to share the namespace and use the socket's
// owner as the distinction: an init step installs rules that let only the
// proxy's UID reach the network, and everything else may reach only the
// proxy.
//
// That holds exactly as long as the workload cannot change the rules or its
// UID. Both are Linux capabilities -- CAP_NET_ADMIN and CAP_SETUID -- so the
// workload container MUST run with every capability dropped. With them it is
// not confined, and this package cannot detect that from inside the
// namespace. The Kubernetes and Compose examples drop them; the docs say why.
// Where that guarantee is not enough, the netns substrate does not depend on
// it.
package sidecar

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Table is the nftables table this package owns.
const Table = "agw_sidecar"

// Config describes the enforcement point sharing the namespace.
type Config struct {
	// ProxyUID is the UID the proxy runs as. Sockets it owns may reach the
	// network; nothing else may. Must not be 0: root is what a workload is
	// most likely to be, and a proxy UID the workload shares confines
	// nothing.
	ProxyUID int

	// ProxyPort is the loopback port the proxy listens on.
	ProxyPort int

	// AllowLoopbackPorts are further loopback ports the workload may reach,
	// e.g. an MCP enforcement point on 8900. Everything else on loopback is
	// refused: other containers in a pod listen there too.
	AllowLoopbackPorts []int
}

func (c Config) validate() error {
	if c.ProxyUID <= 0 {
		return errors.New("sidecar: the proxy UID must be a dedicated non-root UID (Istio uses 1337)")
	}
	ports := append([]int{c.ProxyPort}, c.AllowLoopbackPorts...)
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("sidecar: port %d out of range", p)
		}
	}
	return nil
}

// Rules renders the nftables ruleset. It is a pure function so it can be
// reviewed, tested and diffed on any machine; Apply is what installs it.
//
// The table is deleted and recreated in one transaction, so applying twice is
// the same as applying once, and there is no moment between the two with no
// rules at all.
func Rules(c Config) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	ports := append([]int{c.ProxyPort}, c.AllowLoopbackPorts...)
	sort.Ints(ports)
	var ps []string
	for _, p := range ports {
		ps = append(ps, fmt.Sprint(p))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s\n", Table)
	fmt.Fprintf(&b, "delete table inet %s\n", Table)
	fmt.Fprintf(&b, "table inet %s {\n", Table)
	b.WriteString("\t# Packets refused because something other than the proxy tried to leave.\n")
	b.WriteString("\tcounter refused_direct { }\n\n")
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype filter hook output priority filter; policy drop;\n\n")
	b.WriteString("\t\t# Replies on connections already allowed.\n")
	b.WriteString("\t\tct state established,related accept\n\n")
	fmt.Fprintf(&b, "\t\t# The enforcement point itself. It decides, and records, everything else.\n")
	fmt.Fprintf(&b, "\t\tmeta skuid %d accept\n\n", c.ProxyUID)
	b.WriteString("\t\t# Everyone else: the proxy on loopback, and nothing more.\n")
	fmt.Fprintf(&b, "\t\toif \"lo\" tcp dport { %s } accept\n\n", strings.Join(ps, ", "))
	b.WriteString("\t\tcounter name refused_direct drop\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String(), nil
}
