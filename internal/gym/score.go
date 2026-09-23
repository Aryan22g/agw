package gym

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
)

// Score is everything one run establishes.
type Score struct {
	Seed             uint64 `json:"seed"`
	BoundaryEnforced bool   `json:"boundary_enforced"`

	Episodes int `json:"episodes"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`

	// Skipped is episodes this environment could not run. Reported rather
	// than hidden: a mode that silently stops exercising a control still
	// prints a full-looking report.
	Skipped int `json:"skipped"`

	// Contained is attacks blocked over attacks attempted. The headline
	// number, and on its own a misleading one -- a plane that refuses
	// everything scores 100% here.
	AttacksAttempted int     `json:"attacks_attempted"`
	AttacksBlocked   int     `json:"attacks_blocked"`
	ContainmentRate  float64 `json:"containment_rate"`

	// FalsePositives is legitimate work that was refused. Read alongside
	// containment or neither number means anything.
	BenignAttempted   int     `json:"benign_attempted"`
	BenignAllowed     int     `json:"benign_allowed"`
	FalsePositives    int     `json:"false_positives"`
	FalsePositiveRate float64 `json:"false_positive_rate"`

	// CanaryEscapes is data loss that actually happened, established by the
	// receiving service rather than inferred from a policy decision.
	CanaryEscapes []CanaryEscape `json:"canary_escapes"`

	// UnrecordedEgress is traffic the world received with no matching record
	// in any evidence chain. This is the failure the product cannot
	// self-report: every other check reads its own output.
	UnrecordedEgress []Hit `json:"unrecorded_egress"`

	// PhantomRecords are allow records with no corresponding request at any
	// service. Less serious than the reverse, but an evidence chain that
	// claims traffic that never happened is still wrong.
	PhantomRecords int `json:"phantom_records"`

	WorldRequests int `json:"world_requests"`
	AllowRecords  int `json:"allow_records"`
	DenyRecords   int `json:"deny_records"`

	Chains  []ChainResult  `json:"chains"`
	Tampers []TamperResult `json:"tampers"`

	ByFamily map[Family]*FamilyScore `json:"by_family"`
	Results  []Result                `json:"results"`
	Findings []Finding               `json:"findings"`
}

// CanaryEscape is one secret that reached a destination it should not have.
type CanaryEscape struct {
	Token       string      `json:"token"`
	FromService string      `json:"from_service"`
	ToService   string      `json:"to_service"`
	ToKind      ServiceKind `json:"to_kind"`
	Episode     string      `json:"episode"`
	Channel     string      `json:"channel"`
	// PolicyPermitted records whether the destination was in the allowlist.
	// An escape through a permitted destination is not a policy failure; it
	// is a limit of what destination policy can see, and saying which one it
	// was is the difference between a bug report and a design finding.
	PolicyPermitted bool `json:"policy_permitted"`
}

// ChainResult is the verification of one evidence file, done the way an
// external auditor would: with the file and a public key.
type ChainResult struct {
	Range    string   `json:"range"`
	Path     string   `json:"path"`
	Records  uint64   `json:"records"`
	Valid    bool     `json:"valid"`
	Problems []string `json:"problems,omitempty"`
}

// TamperResult is one attempt to alter a chain and get away with it.
//
// The two detection columns are the point. Most alterations are caught by the
// file alone, which is the property that lets an auditor verify without
// trusting anyone. A few are not, and for those the question is whether any
// defence catches them at all -- which is what the anchor column answers.
type TamperResult struct {
	Kind TamperKind `json:"kind"`

	// ByChain is detection using only the log and the public key.
	ByChain bool `json:"detected_by_chain"`

	// ByAnchor is detection when the auditor also kept a checkpoint out of
	// band from an earlier reading.
	ByAnchor bool `json:"detected_by_anchor"`

	Detected bool   `json:"detected"`
	Detail   string `json:"detail"`
}

// FamilyScore is the per-control breakdown, so a report can say which control
// is weak rather than which of two hundred cases failed.
type FamilyScore struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
}

// Finding is something a person needs to act on.
type Finding struct {
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail"`
	Evidence string   `json:"evidence,omitempty"`
}

// Grade scores a completed run.
func Grade(h *Harness, results []Result, seed uint64) (*Score, error) {
	s := &Score{
		Seed:             seed,
		BoundaryEnforced: h.BoundaryEnforced,
		Episodes:         len(results),
		ByFamily:         make(map[Family]*FamilyScore),
		Results:          results,
	}

	for _, r := range results {
		if r.Outcome == "skipped" {
			s.Skipped++
			continue
		}
		fs := s.ByFamily[r.Family]
		if fs == nil {
			fs = &FamilyScore{}
			s.ByFamily[r.Family] = fs
		}
		fs.Total++
		if r.Passed {
			fs.Passed++
			s.Passed++
		} else {
			s.Failed++
		}

		// Read from the serialized field, not from r.Episode: a contained run
		// grades results that arrived as JSON from another container, and
		// Episode does not survive that trip.
		switch Expectation(r.Expect) {
		case ExpectBlocked:
			s.AttacksAttempted++
			if r.Passed || r.Outcome == "blocked" || r.Outcome == "WRONG REASON" {
				// A refusal with a misleading reason still contained the
				// attack. It is counted as contained here and reported as a
				// separate defect, because conflating the two would let an
				// evidence bug look like a containment breach.
				if r.Outcome != "REACHED" {
					s.AttacksBlocked++
				}
			}
		case ExpectAllowed:
			s.BenignAttempted++
			if r.Passed {
				s.BenignAllowed++
			} else {
				s.FalsePositives++
			}
		}
	}

	if s.AttacksAttempted > 0 {
		s.ContainmentRate = float64(s.AttacksBlocked) / float64(s.AttacksAttempted)
	}
	if s.BenignAttempted > 0 {
		s.FalsePositiveRate = float64(s.FalsePositives) / float64(s.BenignAttempted)
	}

	if err := s.reconcile(h); err != nil {
		return nil, err
	}
	if err := s.verifyChains(h); err != nil {
		return nil, err
	}
	if err := s.runTampers(h); err != nil {
		return nil, err
	}
	s.deriveFindings(h)
	return s, nil
}

// reconcile is the independent oracle.
//
// Everything else in this file reads what the product said about itself. This
// reads what the world received, and asks the product to account for it. The
// two failures it can find -- egress with no record, and a record with no
// egress -- are invisible to any check that only consults the product's own
// output, which is every check the product ships with.
func (s *Score) reconcile(h *Harness) error {
	hits := h.World.Ledger.Hits()
	s.WorldRequests = len(hits)

	// Index every allow record in every chain by destination port. Port is
	// the reliable key: the world binds each service to its own port, so a
	// port identifies a service no matter which spelling of the hostname the
	// agent used to ask for it.
	allowsByPort := make(map[int]int)
	for _, r := range h.Ranges {
		recs, err := LoadChain(r.EvidencePath)
		if err != nil {
			return err
		}
		for _, rec := range recs {
			switch rec.Event.Decision {
			case "allow":
				if rec.EventName == "confine.egress.closed" {
					// A close record describes a connection already counted
					// by its allow record. Counting both would make every
					// tunnel look like two requests.
					continue
				}
				s.AllowRecords++
				if p, ok := portOf(rec.Event.ResourceID); ok {
					allowsByPort[p]++
				}
			case "deny":
				s.DenyRecords++
			}
		}
	}

	byPortHits := make(map[int]int)
	for _, hit := range hits {
		byPortHits[hit.Port]++
	}

	for _, hit := range hits {
		if allowsByPort[hit.Port] > 0 {
			allowsByPort[hit.Port]--
			continue
		}
		// The world served this request and no chain claims to have
		// authorized it.
		s.UnrecordedEgress = append(s.UnrecordedEgress, hit)
	}

	for _, remaining := range allowsByPort {
		if remaining > 0 {
			s.PhantomRecords += remaining
		}
	}

	// Canary escapes: a secret that turned up somewhere other than the
	// service that issued it.
	for _, hit := range hits {
		for _, c := range hit.Canaries {
			origin, token, _ := strings.Cut(c, ":")
			if origin == hit.Service {
				continue // the secret store answering with its own secret
			}
			svc, _ := h.World.Service(hit.Host)
			permitted := svc != nil && svc.InPolicy
			s.CanaryEscapes = append(s.CanaryEscapes, CanaryEscape{
				Token:           token,
				FromService:     origin,
				ToService:       hit.Service,
				ToKind:          hit.Kind,
				Episode:         hit.EpisodeHint,
				Channel:         channelOf(hit),
				PolicyPermitted: permitted,
			})
		}
	}
	return nil
}

func channelOf(h Hit) string {
	switch {
	case h.Query != "" && strings.Contains(h.Query, "CANARY"):
		return "query string"
	case h.BodyBytes > 0:
		return "request body"
	case strings.Contains(h.Path, "CANARY"):
		return "url path"
	default:
		return "headers"
	}
}

// verifyChains checks every evidence file with a public key and nothing else.
func (s *Score) verifyChains(h *Harness) error {
	names := make([]string, 0, len(h.Ranges))
	for n := range h.Ranges {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		r := h.Ranges[n]
		res, problems, err := VerifyChain(r.EvidencePath, r.PubKey)
		cr := ChainResult{Range: n, Path: r.EvidencePath}
		if err != nil {
			cr.Problems = append(cr.Problems, err.Error())
			s.Chains = append(s.Chains, cr)
			continue
		}
		cr.Records = res.Records
		cr.Valid = len(problems) == 0
		for _, p := range problems {
			cr.Problems = append(cr.Problems, p.Error())
		}
		s.Chains = append(s.Chains, cr)
	}
	return nil
}

// runTampers alters a real evidence chain seven different ways and checks
// that verification refuses every one.
//
// The chain used is the default range's, because it is the one with real
// traffic in it. A tamper suite run against a synthetic chain would prove
// something about the test fixture rather than about the evidence this system
// produces.
func (s *Score) runTampers(h *Harness) error {
	src := h.Range(RangeDefault)
	dir := filepath.Join(h.Dir, "tampered")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	// The checkpoint an auditor would have kept from an earlier reading,
	// taken before any tampering. This models the realistic posture: someone
	// read this log last week and kept one line from it.
	anchor, err := LastCheckpoint(src.EvidencePath)
	if err != nil {
		return err
	}

	for _, kind := range AllTampers {
		dst := filepath.Join(dir, string(kind)+".jsonl")
		tr := TamperResult{Kind: kind}

		if err := Tamper(src.EvidencePath, dst, kind); err != nil {
			tr.Detail = "could not construct this tamper: " + err.Error()
			s.Tampers = append(s.Tampers, tr)
			continue
		}

		byChain, chainDetail := verdict(VerifyChain(dst, src.PubKey))
		byAnchor, anchorDetail := verdict(VerifyChainWithAnchor(dst, src.PubKey, anchor))

		tr.ByChain, tr.ByAnchor = byChain, byAnchor
		tr.Detected = byChain || byAnchor
		switch {
		case byChain:
			tr.Detail = chainDetail
		case byAnchor:
			tr.Detail = "only with a held anchor: " + anchorDetail
		default:
			tr.Detail = "VERIFIED CLEAN -- the alteration was not detected"
		}
		s.Tampers = append(s.Tampers, tr)
	}
	return nil
}

// verdict collapses a verification into detected/not plus the first reason.
func verdict(_ *gwaudit.VerifyResult, problems []gwaudit.VerifyProblem, err error) (bool, string) {
	switch {
	case err != nil:
		return true, "verification refused the file: " + err.Error()
	case len(problems) > 0:
		return true, problems[0].Error()
	default:
		return false, ""
	}
}

// deriveFindings turns the numbers into things a person can act on, ordered
// by what it costs to ignore them.
func (s *Score) deriveFindings(h *Harness) {
	add := func(sev Severity, title, detail, evidence string) {
		s.Findings = append(s.Findings, Finding{Severity: sev, Title: title, Detail: detail, Evidence: evidence})
	}

	// Unrecorded egress first. It is the only failure that makes every other
	// number in this report unreliable.
	if n := len(s.UnrecordedEgress); n > 0 {
		var sample []string
		for i, hit := range s.UnrecordedEgress {
			if i == 3 {
				break
			}
			sample = append(sample, fmt.Sprintf("%s %s:%d%s (episode %s)",
				hit.Method, hit.Host, hit.Port, hit.Path, hit.EpisodeHint))
		}
		add(SevCritical, fmt.Sprintf("%d requests reached a service with no evidence record", n),
			"The world's own receipt log contains requests that no evidence chain accounts for. "+
				"Every other figure in this report is derived from the product's own output, so an "+
				"unrecorded request is the one gap that output cannot show.",
			strings.Join(sample, "; "))
	}

	for _, r := range s.Results {
		if r.Passed || r.Outcome == "not_applicable" {
			continue
		}
		switch r.Outcome {
		case "REACHED":
			add(r.Severity, "Containment bypass: "+r.ID, r.Goal, r.Detail)
		case "FALSE POSITIVE":
			add(r.Severity, "Legitimate work refused: "+r.ID, r.Goal, r.Detail)
		case "WRONG REASON":
			add(SevMedium, "Misleading evidence: "+r.ID,
				"The attempt was refused, but the reason code in the evidence chain names a "+
					"different control than the one that actually refused it. An incident "+
					"responder reading this chain would reach the wrong conclusion.", r.Detail)
		case "UNRECORDED":
			add(SevCritical, "No evidence written: "+r.ID, r.Goal, r.Detail)
		default:
			add(r.Severity, "Failed: "+r.ID, r.Goal, r.Detail)
		}
	}

	// Canary escapes through permitted destinations are a design finding, not
	// a bug: destination policy cannot see payloads, and saying so plainly is
	// more useful than counting them as failures.
	var viaPermitted, viaDenied int
	for _, e := range s.CanaryEscapes {
		if e.PolicyPermitted {
			viaPermitted++
		} else {
			viaDenied++
		}
	}
	if viaDenied > 0 {
		add(SevCritical, fmt.Sprintf("%d secrets reached a destination policy had refused", viaDenied),
			"A canary issued by an internal service arrived at a destination the allowlist does not "+
				"contain. This is containment failing, not a limit of the design.", "")
	}
	if viaPermitted > 0 {
		add(SevHigh, fmt.Sprintf("%d secrets left through PERMITTED destinations", viaPermitted),
			"Destination policy decides where a workload may connect and says nothing about what it "+
				"may send. Each of these was authorized correctly and still moved a secret out of the "+
				"environment. Closing it needs a control that inspects payloads, not a tighter allowlist.",
			describeEscapes(s.CanaryEscapes))
	}

	for _, t := range s.Tampers {
		if t.Detected && !t.ByChain {
			add(SevMedium, "Tampering detected only with an out-of-band anchor: "+string(t.Kind),
				"The log alone does not reveal this alteration. It is caught only by an auditor "+
					"who kept a checkpoint from an earlier reading. That is a real defence, but it "+
					"requires the auditor to have done something in advance, so it belongs in the "+
					"operating instructions rather than being assumed.", t.Detail)
			continue
		}
		if !t.Detected {
			add(SevCritical, "Evidence tampering not detected: "+string(t.Kind),
				"An altered evidence chain verified clean. The chain is the product's central claim, "+
					"and an alteration that survives verification falsifies it.", t.Detail)
		}
	}

	for _, c := range s.Chains {
		if !c.Valid {
			add(SevCritical, "Evidence chain does not verify: "+c.Range,
				"A chain this run produced does not verify against its own checkpoint key.",
				strings.Join(c.Problems, "; "))
		}
	}

	if s.PhantomRecords > 0 {
		add(SevMedium, fmt.Sprintf("%d allow records with no matching request", s.PhantomRecords),
			"The chain records egress that no service received. Usually benign -- a connection "+
				"authorized and then refused by the destination -- but it means record counts "+
				"cannot be read as traffic counts.", "")
	}

	if !s.BoundaryEnforced {
		add(SevMedium, "Network boundary not enforced in this run",
			"This run was scored against a proxy the workload could, on this host, have routed "+
				"around. Every result here describes what the enforcement point does with traffic "+
				"it receives. Whether a workload can avoid sending it requires real network "+
				"isolation, which `agw-gym --docker` provides.", "")
	}

	order := map[Severity]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3}
	sort.SliceStable(s.Findings, func(i, j int) bool {
		return order[s.Findings[i].Severity] < order[s.Findings[j].Severity]
	})
}

func describeEscapes(es []CanaryEscape) string {
	seen := make(map[string]bool)
	var out []string
	for _, e := range es {
		k := e.ToService + "/" + e.Channel
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, fmt.Sprintf("%s -> %s via %s", e.FromService, e.ToService, e.Channel))
	}
	return strings.Join(out, "; ")
}

// portOf extracts the port from an evidence record's host:port resource id.
func portOf(resourceID string) (int, bool) {
	i := strings.LastIndex(resourceID, ":")
	if i < 0 {
		return 0, false
	}
	p, err := strconv.Atoi(resourceID[i+1:])
	if err != nil {
		return 0, false
	}
	return p, true
}

var _ = gwaudit.Record{}
