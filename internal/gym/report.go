package gym

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteReport renders a run for a human.
//
// The order is deliberate: what actually happened in the world first, then
// what the product said about it, then the failures. A report that opens with
// a containment percentage invites the reader to stop there, and the
// percentage is the least trustworthy number on the page.
func WriteReport(w io.Writer, s *Score) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	p("\n")
	p("AGENT CONFINEMENT GYM -- run report\n")
	p("seed %d   episodes %d", s.Seed, s.Episodes)
	if s.Skipped > 0 {
		p(" (%d skipped)", s.Skipped)
	}
	p("   world requests served %d\n", s.WorldRequests)
	if s.BoundaryEnforced {
		p("network boundary: ENFORCED (the workload had no route except the proxy)\n")
	} else {
		p("network boundary: not enforced on this host -- results describe what the\n")
		p("                  enforcement point does with traffic it receives\n")
	}
	p("\n")

	p("GROUND TRUTH (from the world, not from the product)\n")
	p("  requests the world received        %d\n", s.WorldRequests)
	p("  egress with no evidence record     %d%s\n", len(s.UnrecordedEgress), flag(len(s.UnrecordedEgress) > 0))
	p("  allow records with no request      %d\n", s.PhantomRecords)
	p("  secrets that left the environment  %d%s\n", len(s.CanaryEscapes), flag(len(s.CanaryEscapes) > 0))
	p("\n")

	p("CONTAINMENT\n")
	p("  attacks blocked                    %d/%d  (%.1f%%)\n",
		s.AttacksBlocked, s.AttacksAttempted, 100*s.ContainmentRate)
	p("  legitimate work allowed            %d/%d  (%.1f%% false positives)\n",
		s.BenignAllowed, s.BenignAttempted, 100*s.FalsePositiveRate)
	p("  evidence records  allow %d  deny %d\n", s.AllowRecords, s.DenyRecords)
	p("\n")

	p("BY CONTROL\n")
	fams := make([]Family, 0, len(s.ByFamily))
	for f := range s.ByFamily {
		fams = append(fams, f)
	}
	sort.Slice(fams, func(i, j int) bool { return fams[i] < fams[j] })
	for _, f := range fams {
		fs := s.ByFamily[f]
		bar := progress(fs.Passed, fs.Total)
		mark := "  "
		if fs.Passed < fs.Total {
			mark = "!!"
		}
		p("  %s %-20s %s %d/%d\n", mark, f, bar, fs.Passed, fs.Total)
	}
	p("\n")

	p("EVIDENCE INTEGRITY\n")
	for _, c := range s.Chains {
		status := "verifies"
		if !c.Valid {
			status = "FAILS: " + strings.Join(c.Problems, "; ")
		}
		p("  chain %-14s %4d records  %s\n", c.Range, c.Records, status)
	}
	p("\n")
	p("  tamper attempts against a real chain:\n")
	p("    %-32s %-9s %-9s %s\n", "alteration", "by file", "by anchor", "")
	for _, t := range s.Tampers {
		mark := func(b bool) string {
			if b {
				return "yes"
			}
			return "no"
		}
		flagged := ""
		if !t.Detected {
			flagged = "  NOT DETECTED: " + truncate(t.Detail, 40)
		} else if !t.ByChain {
			flagged = "  needs an out-of-band anchor"
		}
		p("    %-32s %-9s %-9s%s\n", t.Kind, mark(t.ByChain), mark(t.ByAnchor), flagged)
	}
	p("\n")

	if len(s.CanaryEscapes) > 0 {
		p("SECRETS THAT LEFT THE ENVIRONMENT\n")
		for _, e := range s.CanaryEscapes {
			route := "policy REFUSED this destination"
			if e.PolicyPermitted {
				route = "destination was permitted by policy"
			}
			p("  %s -> %s  via %s  (%s)  [%s]\n",
				e.FromService, e.ToService, e.Channel, route, e.Episode)
		}
		p("\n")
	}

	if len(s.Findings) > 0 {
		p("FINDINGS\n")
		for i, f := range s.Findings {
			p("\n  %d. [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title)
			for _, line := range wrap(f.Detail, 76) {
				p("     %s\n", line)
			}
			if f.Evidence != "" {
				for _, line := range wrap("evidence: "+f.Evidence, 76) {
					p("     %s\n", line)
				}
			}
		}
		p("\n")
	} else {
		p("FINDINGS\n  none\n\n")
	}
}

// WriteFailures prints only what did not pass, for iterating quickly.
func WriteFailures(w io.Writer, s *Score) {
	var any bool
	for _, r := range s.Results {
		if r.Passed {
			continue
		}
		any = true
		fmt.Fprintf(w, "%-36s %-18s %-14s %s\n", r.ID, r.Family, r.Outcome, truncate(r.Detail, 80))
	}
	if !any {
		fmt.Fprintln(w, "every episode passed")
	}
}

// WriteAll prints every episode, passing or not.
func WriteAll(w io.Writer, s *Score) {
	for _, r := range s.Results {
		mark := "pass"
		if !r.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(w, "%-4s %-36s %-18s %-14s %s\n",
			mark, r.ID, r.Family, r.Outcome, truncate(r.Detail, 70))
	}
}

func flag(bad bool) string {
	if bad {
		return "   <-- look here"
	}
	return ""
}

func progress(got, total int) string {
	const width = 20
	if total == 0 {
		return strings.Repeat(" ", width)
	}
	n := got * width / total
	return "[" + strings.Repeat("#", n) + strings.Repeat(".", width-n) + "]"
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	line := words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}
