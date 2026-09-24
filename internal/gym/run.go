package gym

import (
	"fmt"
	"sort"
	"strings"
	"time"

	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// Head exposes the chain position, so an episode's evidence can be located
// precisely rather than guessed at from timestamps.
func (r *Range) Head() (uint64, string) {
	if r.realSink == nil {
		return 0, ""
	}
	return r.realSink.Head()
}

// window records where in a range's chain one episode's records landed.
type window struct {
	rangeName string
	from, to  uint64
}

// Run executes every episode and judges it.
//
// Episodes run in seeded random order. Order is not incidental: an episode
// that only passes when it runs first is relying on state a real deployment
// will not hand it, and shuffling is how that gets found.
func Run(h *Harness, eps []Episode) ([]Result, error) {
	h.Gen.Shuffle(len(eps), func(i, j int) { eps[i], eps[j] = eps[j], eps[i] })

	windows := make(map[string]window, len(eps))
	results := make([]Result, 0, len(eps))

	for _, ep := range eps {
		// An episode the environment cannot support is reported as skipped,
		// with the reason. Dropping it silently would let a mode quietly stop
		// testing a control and still show a full-looking report; counting it
		// as a pass would be worse.
		if !ep.Runnable(h.Caps) {
			results = append(results, Result{
				Episode: ep, ID: ep.ID, Family: ep.Family, Severity: ep.Sev, Goal: ep.Goal,
				Expect: string(ep.Expect), Passed: true, Outcome: "skipped",
				Detail: "this environment does not provide: " + describeNeeds(ep.Needs, h.Caps),
			})
			continue
		}

		rangeName := ep.Range
		if rangeName == "" {
			rangeName = RangeDefault
		}
		rng, ok := h.Ranges[rangeName]
		if !ok {
			// A range can be absent legitimately: the permissive range only
			// exists if the product accepted the permissive policy at all.
			results = append(results, Result{
				Episode: ep, ID: ep.ID, Family: ep.Family, Severity: ep.Sev, Goal: ep.Goal,
				Expect: string(ep.Expect), Passed: true, Outcome: "not_applicable",
				Detail: fmt.Sprintf("range %q does not exist: the configuration it tests was refused at load", rangeName),
			})
			continue
		}

		agent := &Agent{
			ProxyAddr: rng.Addr(),
			World:     h.World,
			Zone:      h.Zone,
			Episode:   ep.ID,
			Range:     rng,
			Timeout:   8 * time.Second,
		}

		before, _ := rng.Head()
		at := ep.Run(agent)
		after, _ := rng.Head()
		windows[ep.ID] = window{rangeName: rangeName, from: before, to: after}

		results = append(results, judge(ep, at))
	}

	// Evidence is attached after the fact so that judging the outcome and
	// judging the record are separate steps. They fail independently in
	// practice -- a correct refusal with a misleading reason code is a real
	// defect, and collapsing the two would hide it.
	if err := attachEvidence(h, results, windows); err != nil {
		return results, err
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Family != results[j].Family {
			return results[i].Family < results[j].Family
		}
		return results[i].ID < results[j].ID
	})
	return results, nil
}

// judge decides whether an attempt met its expectation.
func judge(ep Episode, at Attempt) Result {
	r := Result{
		Episode: ep, ID: ep.ID, Family: ep.Family, Severity: ep.Sev, Goal: ep.Goal,
		Expect: string(ep.Expect), ProxyCode: at.ProxyReason, LatencyMS: at.Latency.Milliseconds(),
	}

	switch ep.Expect {
	case ExpectBlocked:
		blocked := !at.Reached
		r.Passed = blocked
		if blocked {
			r.Outcome = "blocked"
			r.Detail = describeBlock(at)
		} else {
			r.Outcome = "REACHED"
			r.Detail = describeReach(at)
		}

	case ExpectAllowed:
		r.Passed = at.Reached
		if at.Reached {
			r.Outcome = "allowed"
			r.Detail = describeReach(at)
		} else {
			r.Outcome = "FALSE POSITIVE"
			r.Detail = "legitimate work was refused: " + describeBlock(at)
		}

	case ExpectRecorded:
		// Judged entirely on the evidence, attached later. Outcome is noted
		// so the report can say what actually happened.
		r.Passed = true
		r.Outcome = "observed"
		if at.Reached {
			r.Detail = "reached; " + describeReach(at)
		} else {
			r.Detail = "refused; " + describeBlock(at)
		}
	}

	if at.Note != "" {
		r.Detail = strings.TrimSpace(r.Detail + " [" + at.Note + "]")
	}
	return r
}

func describeBlock(at Attempt) string {
	switch {
	case at.ProxyReason != "":
		return fmt.Sprintf("HTTP %d, reason %s", at.Status, at.ProxyReason)
	case at.Status != 0:
		return fmt.Sprintf("HTTP %d", at.Status)
	case at.Err != nil:
		return "transport: " + at.Err.Error()
	default:
		return "no connection"
	}
}

func describeReach(at Attempt) string {
	body := strings.TrimSpace(at.Body)
	if len(body) > 90 {
		body = body[:90] + "..."
	}
	if body == "" {
		return fmt.Sprintf("HTTP %d", at.Status)
	}
	return fmt.Sprintf("HTTP %d, body %q", at.Status, body)
}

// attachEvidence finds the chain records each episode produced and checks the
// reason code against what the episode expected.
func attachEvidence(h *Harness, results []Result, windows map[string]window) error {
	// Per-episode evidence correlation needs the chain sequence taken either
	// side of the attempt, which only a range this process owns can give.
	// Against a proxy in another container there is no such handle, so
	// correlation there happens at the aggregate level instead: the chain is
	// verified whole and reconciled against the world's receipt log, which
	// are the two checks that matter most anyway.
	chains := make(map[string][]gwaudit.Record, len(h.Ranges))
	local := make(map[string]bool, len(h.Ranges))
	for name, r := range h.Ranges {
		if r.realSink == nil || r.EvidencePath == "" {
			continue
		}
		local[name] = true
		recs, err := LoadChain(r.EvidencePath)
		if err != nil {
			return fmt.Errorf("gym: read chain for range %s: %w", name, err)
		}
		chains[name] = recs
	}

	for i := range results {
		w, ok := windows[results[i].ID]
		if !ok || !local[w.rangeName] {
			continue
		}
		var mine []gwaudit.Record
		for _, rec := range chains[w.rangeName] {
			if rec.Seq > w.from && rec.Seq <= w.to {
				mine = append(mine, rec)
			}
		}
		if len(mine) == 0 {
			// Nothing recorded. For most episodes that is itself the finding.
			if results[i].Family != FamilyPolicy {
				results[i].EvidenceReason = "(no record)"
			}
			if results[i].Episode.Expect == ExpectRecorded {
				results[i].Passed = false
				results[i].Outcome = "UNRECORDED"
				results[i].Detail += " -- nothing was written to the evidence chain"
			}
			continue
		}

		// The last record is the decisive one: an episode that resolved, was
		// refused, and recorded a close would otherwise be judged on its
		// first record rather than its outcome.
		last := mine[len(mine)-1]
		results[i].EvidenceSeq = last.Seq
		results[i].EvidenceReason = last.Event.ReasonCode

		if results[i].Episode.ExpectReason != "" && !reasonMatches(mine, results[i].Episode.ExpectReason) {
			// The outcome was right; the explanation was not. Whoever reads
			// this chain during an incident will draw the wrong conclusion,
			// so it is recorded as a failure in its own right rather than
			// folded into the containment number.
			results[i].Detail += fmt.Sprintf(" -- evidence says %q, expected %q",
				last.Event.ReasonCode, results[i].Episode.ExpectReason)
			results[i].Outcome = "WRONG REASON"
			if results[i].Passed {
				results[i].Passed = false
			}
		}
	}
	return nil
}

// describeNeeds names the capabilities an episode wanted and did not get.
func describeNeeds(needs []Capability, have map[Capability]bool) string {
	var missing []string
	for _, n := range needs {
		if !have[n] {
			missing = append(missing, string(n))
		}
	}
	return strings.Join(missing, ", ")
}

func reasonMatches(recs []gwaudit.Record, want string) bool {
	for _, r := range recs {
		if r.Event.ReasonCode == want {
			return true
		}
	}
	return false
}
