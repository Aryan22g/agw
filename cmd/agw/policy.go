package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Aryan22g/agw/internal/cli/auditcli"
	"github.com/Aryan22g/agw/internal/confine"
	"github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/internal/gateway/authz"
	"github.com/Aryan22g/agw/internal/gateway/routing"
)

// runPolicy is policy authoring: check a file, ask why something would be
// refused, or draft a policy from what agents actually did.
//
// There are two policy languages and one command for both. Egress policy
// (confinement: which hosts a workload may reach) and action policy (the
// gateway and MCP: which tools an agent may call) are different documents
// with different fields, and the file itself says which it is. Making the
// operator say it as well would be one more thing to get wrong.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agw policy lint|explain|suggest ...  (agw policy -h for detail)")
	}
	switch args[0] {
	case "lint", "check", "validate":
		return runPolicyLint(args[1:])
	case "explain":
		return runPolicyExplain(args[1:])
	case "suggest":
		return runPolicySuggest(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, `agw policy -- author and check policy

  agw policy lint FILE...
        Check egress or action policy files the way the enforcement points
        will load them. Exit status 1 on any error.

  agw policy explain --policy FILE --workload ID DESTINATION
        Egress: would this workload be allowed to reach host[:port]? Names the
        rule that permits it, or the structural denial that refuses it.

  agw policy explain --policy FILE --agent ID --action A --resource R [--risk read]
        Action: would this tool call be allowed? Lists every rule that matched.

  agw policy suggest EVIDENCE.jsonl [--workload ID] [--out FILE]
        Draft an egress policy from observed traffic, with the destinations the
        structural guard refuses left out and flagged.
`)
		return nil
	}
	return fmt.Errorf("unknown policy subcommand %q (want lint, explain or suggest)", args[0])
}

type policyKind int

const (
	kindUnknown policyKind = iota
	kindEgress
	kindAction
)

// detectKind reads just enough of a policy to know which language it is in.
func detectKind(data []byte) policyKind {
	var probe struct {
		Workloads []any  `yaml:"workloads"`
		Tenant    string `yaml:"tenant"`
		Rules     []any  `yaml:"rules"`
	}
	if yaml.Unmarshal(data, &probe) != nil {
		return kindUnknown
	}
	switch {
	case probe.Workloads != nil:
		return kindEgress
	case probe.Tenant != "" || probe.Rules != nil:
		return kindAction
	}
	return kindUnknown
}

func runPolicyLint(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: agw policy lint FILE [FILE ...]")
	}
	var failed int
	for _, path := range args {
		errs, warns := lintOne(path)
		for _, w := range warns {
			fmt.Printf("%s: warning: %s\n", path, w)
		}
		for _, e := range errs {
			fmt.Printf("%s: error: %s\n", path, e)
		}
		if len(errs) == 0 {
			fmt.Printf("%s: ok\n", path)
		} else {
			failed++
		}
	}
	if failed > 0 {
		return &auditcli.ExitError{Code: 1, Msg: fmt.Sprintf("%d policy file(s) failed", failed)}
	}
	return nil
}

// lintOne loads a policy exactly as the enforcement point will, then adds the
// warnings that are not errors but are usually mistakes.
func lintOne(path string) (errs, warns []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{err.Error()}, nil
	}

	switch detectKind(data) {
	case kindEgress:
		p, err := confine.LoadPolicy(path)
		if err != nil {
			return []string{err.Error()}, nil
		}
		// The second half of startup: permit_private is validated when the
		// guard is built, so a lint that stopped at LoadPolicy would pass a
		// file the proxy refuses to start with.
		if _, err := confine.NewGuard(p.PermitPrivate); err != nil {
			return []string{err.Error()}, nil
		}
		for _, w := range p.Workloads {
			if len(w.Allow) == 0 {
				warns = append(warns, fmt.Sprintf(
					"workload %q allows nothing -- correct if intended, but it will be refused everywhere", w.ID))
			}
			for _, r := range w.Allow {
				if len(r.Ports) == 0 {
					warns = append(warns, fmt.Sprintf(
						"workload %q: %s has no ports, so every port is allowed; name 443 if that is what you mean",
						w.ID, r.Host))
				}
				if strings.HasPrefix(r.Host, "*.") {
					warns = append(warns, fmt.Sprintf(
						"workload %q: %s does not match the apex %s; list it separately if needed",
						w.ID, r.Host, r.Host[2:]))
				}
			}
		}
		for _, cidr := range p.PermitPrivate {
			warns = append(warns, fmt.Sprintf(
				"permit_private %s exempts that range from the structural denials for every workload", cidr))
		}

	case kindAction:
		if _, err := authz.LoadPolicyFile(path); err != nil {
			return []string{err.Error()}, nil
		}

	default:
		return []string{"not recognisably an egress policy (needs `workloads:`) or an action policy (needs `tenant:` and `rules:`)"}, nil
	}
	return nil, warns
}

func runPolicyExplain(args []string) error {
	fs := flag.NewFlagSet("agw policy explain", flag.ContinueOnError)
	var (
		policyPath = fs.String("policy", "", "policy file")
		workload   = fs.String("workload", "", "egress: the workload id")
		agent      = fs.String("agent", "", "action: the agent id")
		action     = fs.String("action", "", "action: e.g. github.issue.create")
		resource   = fs.String("resource", "", "action: e.g. acme/app")
		risk       = fs.String("risk", "read", "action: read, write, privileged or destructive")
	)
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}
	data, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}

	switch detectKind(data) {
	case kindEgress:
		if *workload == "" || len(positional) != 1 {
			return errors.New("usage: agw policy explain --policy FILE --workload ID HOST[:PORT]")
		}
		return explainEgress(*policyPath, *workload, positional[0])
	case kindAction:
		if *agent == "" || *action == "" {
			return errors.New("usage: agw policy explain --policy FILE --agent ID --action A --resource R [--risk read]")
		}
		return explainAction(*policyPath, *agent, *action, *resource, routing.RiskClass(*risk))
	}
	return errors.New("the policy file is neither an egress nor an action policy")
}

// explainEgress answers the question an operator asks when an agent was
// refused: which control said no, and what would have to change.
//
// It evaluates in the proxy's order -- structural guard for literals, then
// policy -- and says when an answer depends on DNS, because a permitted
// hostname can still be refused at connect time if it resolves somewhere the
// guard forbids.
func explainEgress(path, workload, dest string) error {
	p, err := confine.LoadPolicy(path)
	if err != nil {
		return err
	}
	guard, err := confine.NewGuard(p.PermitPrivate)
	if err != nil {
		return err
	}

	defaultPort := 443
	if strings.HasPrefix(dest, "http://") {
		defaultPort = 80
	}
	dest = strings.TrimPrefix(strings.TrimPrefix(dest, "https://"), "http://")
	if i := strings.IndexByte(dest, '/'); i >= 0 {
		dest = dest[:i]
	}
	host, port, err := confine.SplitHostPort(dest, defaultPort)
	if err != nil {
		return err
	}
	host = strings.Trim(host, "[]")

	fmt.Printf("workload     %s\ndestination  %s:%d\n\n", workload, host, port)

	if addr, perr := netip.ParseAddr(host); perr == nil {
		if gerr := guard.Check(addr); gerr != nil {
			fmt.Printf("DENY  %s\n\n", confine.Reason(gerr))
			fmt.Printf("  Refused by the structural guard before policy is consulted:\n  %v\n", gerr)
			fmt.Printf("\n  No allow rule can change this. It is not policy; it is the boundary.\n")
			return nil
		}
	}

	note, perr := p.Permits(workload, host, port)
	if perr != nil {
		fmt.Printf("DENY  not_in_allowlist\n\n")
		if !contains(p.WorkloadIDs(), workload) {
			fmt.Printf("  Workload %q has no entry in this policy, so it may reach nothing.\n", workload)
			fmt.Printf("  Known workloads: %s\n", strings.Join(sortedCopy(p.WorkloadIDs()), ", "))
			return nil
		}
		if p.PermitsHost(workload, host) {
			fmt.Printf("  A rule names %s, but not on port %d.\n", host, port)
		} else {
			fmt.Printf("  No rule for %q names %s.\n", workload, host)
		}
		fmt.Printf("\n  To allow it, add under workload %q:\n\n", workload)
		fmt.Printf("    - host: %s\n      ports: [%d]\n      note: why this agent needs it\n", host, port)
		return nil
	}

	fmt.Printf("ALLOW\n\n")
	if note != "" {
		fmt.Printf("  Permitted by a rule noted %q.\n", note)
	} else {
		fmt.Printf("  Permitted by policy.\n")
	}
	if _, perr := netip.ParseAddr(host); perr != nil {
		fmt.Printf("\n  Still subject to DNS at connect time: if %s resolves to link-local, private,\n", host)
		fmt.Printf("  loopback or NAT64 space outside permit_private, the connection is refused.\n")
	}
	return nil
}

func explainAction(path, agent, action, resource string, risk routing.RiskClass) error {
	p, err := authz.LoadPolicyFile(path)
	if err != nil {
		return err
	}
	engine, err := authz.NewNativeEngine(map[string]*authz.Policy{p.Tenant: p})
	if err != nil {
		return err
	}
	req := authz.Request{
		TenantID: p.Tenant, AgentID: agent, Action: action,
		Resource: resource, RiskClass: risk, Now: time.Now().UTC(),
	}
	d := engine.Authorize(context.Background(), req)

	fmt.Printf("tenant    %s\nagent     %s\naction    %s\nresource  %s\nrisk      %s\n\n",
		p.Tenant, agent, action, orNone(resource), risk)

	verdict := strings.ToUpper(string(d.Outcome))
	fmt.Printf("%s  %s\n", verdict, d.Reason)
	if d.Detail != "" {
		fmt.Printf("  %s\n", d.Detail)
	}

	var matched []string
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Matches(req) {
			matched = append(matched, fmt.Sprintf("%s (%s)", r.ID, r.Effect))
		}
	}
	if len(matched) > 0 {
		fmt.Printf("\n  Matching rules: %s\n", strings.Join(matched, ", "))
		fmt.Printf("  Deny overrides allow; with no match the answer is deny.\n")
	} else {
		fmt.Printf("\n  No rule matched. Default deny.\n")
	}
	return nil
}

// runPolicySuggest drafts an egress policy from observed evidence.
//
// This is the Day-3 step of the adoption ladder: an operator has been
// watching for a while and wants a starting policy that matches what their
// agents actually do. Two things keep it from being a rubber stamp. Anything
// the structural guard refuses -- metadata, private space -- is left out and
// listed, because "the agent did it last week" is not a reason to permit a
// credential endpoint. And every entry carries its observation count, so a
// destination seen once is visibly different from one seen ten thousand times.
func runPolicySuggest(args []string) error {
	fs := flag.NewFlagSet("agw policy suggest", flag.ContinueOnError)
	var (
		workload = fs.String("workload", "", "workload id for the drafted policy (default: most active agent)")
		out      = fs.String("out", "", "write the draft here (default: stdout)")
		minCount = fs.Int("min", 1, "leave out destinations seen fewer than this many times")
	)
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(positional) == 0 {
		return errors.New("usage: agw policy suggest EVIDENCE.jsonl [--workload ID] [--out FILE]")
	}

	type dest struct {
		host  string
		port  int
		count int
	}
	seen := map[string]*dest{}
	refused := map[string]string{}
	// Destinations the policy in force refused. Drafting them would turn an
	// agent's own exfiltration attempts into allow rules, so they are listed
	// for a human to decide about rather than drafted.
	policyRefused := map[string]string{}
	byAgent := map[string]int{}
	guard, _ := confine.NewGuard(nil)

	for _, path := range positional {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		recs, err := audit.ReadRecords(f)
		f.Close()
		if err != nil {
			return err
		}
		for _, rec := range recs {
			host, port, ok := destinationOf(rec)
			if !ok {
				continue
			}
			if *workload != "" && rec.Event.AgentID != *workload {
				continue
			}
			byAgent[rec.Event.AgentID]++
			// An ENFORCED refusal means the agent never got there, and the
			// attempt is exactly what the policy exists to stop, so it is
			// listed for a human rather than drafted. A shadow-mode
			// would_deny is different: nothing was blocked, the agent really
			// did reach it, and drafting from that traffic is the point.
			if rec.Event.Decision == "deny" {
				policyRefused[fmt.Sprintf("%s:%d", host, port)] = rec.Event.ReasonCode
				continue
			}
			if addr, err := netip.ParseAddr(host); err == nil {
				if gerr := guard.Check(addr); gerr != nil {
					refused[fmt.Sprintf("%s:%d", host, port)] = confine.Reason(gerr)
					continue
				}
			}
			k := fmt.Sprintf("%s:%d", host, port)
			if seen[k] == nil {
				seen[k] = &dest{host: host, port: port}
			}
			seen[k].count++
		}
	}

	wl := *workload
	if wl == "" {
		best := 0
		for a, n := range byAgent {
			if n > best || (n == best && a < wl) {
				wl, best = a, n
			}
		}
	}
	if wl == "" {
		return errors.New("no destinations found in the evidence; record some traffic with `agw watch` or `agw run` first")
	}

	list := make([]*dest, 0, len(seen))
	for _, d := range seen {
		if d.count >= *minCount {
			list = append(list, d)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].count != list[j].count {
			return list[i].count > list[j].count
		}
		return list[i].host < list[j].host
	})

	var b strings.Builder
	fmt.Fprintf(&b, "# Drafted by `agw policy suggest` from %s on %s.\n",
		strings.Join(positional, ", "), time.Now().UTC().Format("2006-01-02"))
	b.WriteString("# A draft, not a decision: review every entry. Counts are observations.\n")
	b.WriteString("# Rehearse it before enforcing: agw watch --policy THIS_FILE\n")
	b.WriteString("version: \"1\"\n\nworkloads:\n")
	fmt.Fprintf(&b, "  - id: %s\n    allow:\n", yamlQuote(wl))
	if len(list) == 0 {
		b.WriteString("      [] # nothing observed that the guard would permit\n")
	}
	for _, d := range list {
		fmt.Fprintf(&b, "      - host: %s\n        ports: [%d]\n        note: observed %d time(s)\n",
			yamlQuote(d.host), d.port, d.count)
	}
	b.WriteString("\npermit_private: []\n")
	if len(refused) > 0 {
		b.WriteString("\n# Observed but deliberately NOT drafted -- the structural guard refuses these\n")
		b.WriteString("# and no allow rule can change that:\n")
		keysSorted := make([]string, 0, len(refused))
		for k := range refused {
			keysSorted = append(keysSorted, k)
		}
		sort.Strings(keysSorted)
		for _, k := range keysSorted {
			fmt.Fprintf(&b, "#   %-40s %s\n", k, refused[k])
		}
	}

	var unlisted []string
	for k := range policyRefused {
		if _, drafted := seen[k]; !drafted {
			if _, guarded := refused[k]; !guarded {
				unlisted = append(unlisted, k)
			}
		}
	}
	if len(unlisted) > 0 {
		sort.Strings(unlisted)
		b.WriteString("\n# Attempted but refused by the policy that was in force. Not drafted: an\n")
		b.WriteString("# agent's refused attempts are exactly what a policy exists to stop. Add any\n")
		b.WriteString("# of these only as a deliberate decision:\n")
		for _, k := range unlisted {
			fmt.Fprintf(&b, "#   %-40s %s\n", k, policyRefused[k])
		}
	}

	if *out == "" {
		fmt.Print(b.String())
		return nil
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a policy", *out)
	}
	if err := os.WriteFile(*out, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "agw: drafted %d destination(s) for %s into %s", len(list), wl, *out)
	if len(refused) > 0 {
		fmt.Fprintf(os.Stderr, " (%d guard-refused destination(s) left out)", len(refused))
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "agw: check it with  agw policy lint %s\n", *out)
	return nil
}

// destinationOf extracts host and port from any record that describes a
// network destination: confinement egress records carry host:port, recorder
// observations carry a URL or server address in ResourceID.
func destinationOf(rec audit.Record) (string, int, bool) {
	e := rec.Event
	id := strings.TrimSpace(e.ResourceID)
	if id == "" {
		return "", 0, false
	}
	switch {
	case strings.HasPrefix(e.Action, "net.") || strings.HasPrefix(e.Action, "http."):
	case e.ResourceType == "host":
	default:
		return "", 0, false
	}

	defaultPort := 443
	if strings.HasPrefix(id, "http://") {
		defaultPort = 80
	}
	// A span that recorded only the path carries the host separately.
	if strings.HasPrefix(id, "/") {
		id = strings.TrimSpace(e.BackendID)
	}
	id = strings.TrimPrefix(strings.TrimPrefix(id, "https://"), "http://")
	if i := strings.IndexAny(id, "/?#"); i >= 0 {
		id = id[:i]
	}
	if id == "" || strings.ContainsAny(id, " \t") {
		return "", 0, false
	}
	host, port, err := confine.SplitHostPort(id, defaultPort)
	if err != nil {
		return "", 0, false
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", 0, false
	}
	return host, port, true
}

func yamlQuote(s string) string {
	if s == "" || strings.ContainsAny(s, ":#*[]{},&!|>'\"%@`") || strings.HasPrefix(s, "-") {
		return strconv.Quote(s)
	}
	return s
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func sortedCopy(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
