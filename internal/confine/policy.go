package confine

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule permits one destination. Both fields must match for the rule to apply.
type Rule struct {
	// Host is an exact hostname ("pypi.org"), a subdomain wildcard
	// ("*.pythonhosted.org"), or an exact IP literal ("140.82.121.4").
	//
	// A subdomain wildcard matches on the dot boundary and does NOT match the
	// apex: "*.example.com" permits "files.example.com" but not
	// "example.com" and not "evilexample.com". Naming the apex separately is
	// one extra line and removes a whole class of near-miss mistakes.
	Host string `yaml:"host"`

	// Ports restricts which ports may be reached. Empty permits any port,
	// which should be rare -- an allowlist entry that does not say 443 is an
	// allowlist entry nobody has thought about.
	Ports []int `yaml:"ports,omitempty"`

	// Note is operator documentation, carried into the evidence record so a
	// reviewer can see why a destination was permitted.
	Note string `yaml:"note,omitempty"`
}

// Workload is the egress policy for one confined workload.
type Workload struct {
	ID    string `yaml:"id"`
	Allow []Rule `yaml:"allow"`
}

// Policy is a complete egress policy file.
//
// There is no global allow and no wildcard workload. A workload with no entry
// in this file can reach nothing, which means adding a workload to a
// deployment never implicitly grants it network access.
type Policy struct {
	Version   string     `yaml:"version"`
	Workloads []Workload `yaml:"workloads"`

	// PermitPrivate lists narrow CIDRs exempted from the structural denials
	// in guard.go. Empty is the correct value for almost every deployment.
	PermitPrivate []string `yaml:"permit_private,omitempty"`

	byWorkload map[string]*Workload
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("confine: read policy: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("confine: parse policy %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("confine: policy %s: %w", path, err)
	}
	return &p, nil
}

// Validate checks the policy and builds its lookup index.
func (p *Policy) Validate() error {
	if p.Version != "1" {
		return fmt.Errorf("unsupported policy version %q (want \"1\")", p.Version)
	}
	if len(p.Workloads) == 0 {
		return fmt.Errorf("policy declares no workloads")
	}

	p.byWorkload = make(map[string]*Workload, len(p.Workloads))

	for i := range p.Workloads {
		w := &p.Workloads[i]

		if strings.TrimSpace(w.ID) == "" {
			return fmt.Errorf("workload %d has no id", i)
		}
		if w.ID == "*" {
			// A wildcard workload would mean "any workload that shows up gets
			// this policy", which defeats provenance identity: an unregistered
			// workload should be refused, not handed a default grant.
			return fmt.Errorf("workload id %q is not permitted: name each workload explicitly", w.ID)
		}
		if _, dup := p.byWorkload[w.ID]; dup {
			return fmt.Errorf("workload %q declared twice", w.ID)
		}

		for j, r := range w.Allow {
			host := strings.TrimSpace(strings.ToLower(r.Host))
			if host == "" {
				return fmt.Errorf("workload %q rule %d has no host", w.ID, j)
			}
			if host == "*" {
				return fmt.Errorf(
					"workload %q rule %d: host \"*\" is not permitted; list the destinations", w.ID, j)
			}
			if strings.HasPrefix(host, "*.") {
				rest := host[2:]
				if rest == "" || !strings.Contains(rest, ".") {
					return fmt.Errorf(
						"workload %q rule %d: %q is too broad for a wildcard", w.ID, j, r.Host)
				}
			} else if strings.Contains(host, "*") {
				return fmt.Errorf(
					"workload %q rule %d: %q -- wildcards are only supported as a leading \"*.\" label",
					w.ID, j, r.Host)
			}
			for _, port := range r.Ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("workload %q rule %d: port %d out of range", w.ID, j, port)
				}
			}
			w.Allow[j].Host = host
		}

		p.byWorkload[w.ID] = w
	}

	return nil
}

// Permits reports whether a workload may reach host:port, and returns the
// matching rule's note for the evidence record.
//
// Returns ErrNotPermitted for both "no such workload" and "no matching rule".
// The distinction is deliberately not exposed to the caller being refused:
// an unregistered workload learning that it is unregistered is a small
// information leak with no legitimate use.
func (p *Policy) Permits(workloadID, host string, port int) (note string, err error) {
	w, ok := p.byWorkload[workloadID]
	if !ok {
		return "", fmt.Errorf("%w: workload %q has no policy", ErrNotPermitted, workloadID)
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))

	for _, r := range w.Allow {
		if !hostMatches(r.Host, host) {
			continue
		}
		if !portMatches(r.Ports, port) {
			continue
		}
		return r.Note, nil
	}

	return "", fmt.Errorf("%w: %s:%d", ErrNotPermitted, host, port)
}

// PermitsHost reports whether any rule for a workload names this host, with
// the port left out of the question.
//
// Used by shadow evaluation, where a destination is sometimes known only as a
// hostname. A false answer is still definitive -- no rule permits this host on
// any port -- while a true answer is not, because the port might still be
// wrong. The caller is expected to treat those two differently rather than
// collapsing them into an allow.
func (p *Policy) PermitsHost(workloadID, host string) bool {
	w, ok := p.byWorkload[workloadID]
	if !ok {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, r := range w.Allow {
		if hostMatches(r.Host, host) {
			return true
		}
	}
	return false
}

// WorkloadIDs returns every workload id the policy names.
func (p *Policy) WorkloadIDs() []string {
	out := make([]string, 0, len(p.byWorkload))
	for id := range p.byWorkload {
		out = append(out, id)
	}
	return out
}

// hostMatches implements the matching rules documented on Rule.Host.
func hostMatches(pattern, host string) bool {
	if pattern == host {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"

		// Must be longer than the suffix (so there is a real label in front)
		// and must end on the dot boundary. This is what stops
		// "evilexample.com" from matching "*.example.com".
		if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
			return true
		}
		return false
	}

	// A bare IP literal in a rule matches only the identical literal. Parsing
	// both sides means 140.82.121.4 and ::ffff:140.82.121.4 are not treated
	// as the same destination by accident, in either direction.
	if pa, err := netip.ParseAddr(pattern); err == nil {
		if ha, err := netip.ParseAddr(host); err == nil {
			return pa.Unmap() == ha.Unmap()
		}
		return false
	}

	return false
}

func portMatches(ports []int, port int) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// SplitHostPort splits an authority into host and port, defaulting the port
// when absent. A destination with no port is ambiguous, so callers that care
// about the difference should check before calling.
func SplitHostPort(authority string, defaultPort int) (string, int, error) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// No port present.
		return strings.ToLower(authority), defaultPort, nil
	}

	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return "", 0, fmt.Errorf("confine: bad port %q", portStr)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("confine: port %d out of range", port)
	}

	return strings.ToLower(host), port, nil
}
