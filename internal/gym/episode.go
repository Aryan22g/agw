package gym

import (
	"fmt"
	"time"
)

// Expectation is what should happen to an episode's traffic.
type Expectation string

const (
	// ExpectBlocked means the confinement plane must refuse this. An episode
	// that expects to be blocked and is not is a containment failure.
	ExpectBlocked Expectation = "blocked"

	// ExpectAllowed means this is legitimate work that must succeed. These
	// are not filler: a plane that refuses everything contains perfectly and
	// is useless, so the false-positive rate is a first-class result.
	ExpectAllowed Expectation = "allowed"

	// ExpectRecorded means the outcome matters less than the evidence. Used
	// where either answer is defensible but silence is not.
	ExpectRecorded Expectation = "recorded"
)

// Severity ranks what it costs to get an episode wrong.
type Severity string

const (
	SevCritical Severity = "critical" // credential theft, data loss, unrecorded egress
	SevHigh     Severity = "high"     // containment bypass with no data loss proven
	SevMedium   Severity = "medium"   // attribution or reason-code errors
	SevLow      Severity = "low"      // cosmetic or informational
)

// Family groups episodes by the class of attack they represent, so a report
// can say which control is weak rather than which of 200 cases failed.
type Family string

const (
	FamilyMetadata   Family = "cloud_metadata"
	FamilyExfil      Family = "exfiltration"
	FamilyAllowlist  Family = "allowlist_matching"
	FamilyDNS        Family = "dns"
	FamilyIdentity   Family = "workload_identity"
	FamilyProxy      Family = "proxy_semantics"
	FamilyEvidence   Family = "evidence_integrity"
	FamilyFailClosed Family = "fail_closed"
	FamilyKillSwitch Family = "kill_switch"
	FamilyBenign     Family = "benign_work"
	FamilyBoundary   Family = "network_boundary"
	FamilyPolicy     Family = "policy_safety"
)

// Capability is something an episode needs from the environment it runs in.
//
// The two modes can do different things. Hosted mode links the enforcement
// code directly, so it can revoke a workload, break the evidence sink and
// answer DNS however it likes -- but it cannot stop the agent routing around
// the proxy, because that needs a network boundary. Contained mode has the
// boundary and none of the in-process reach.
//
// Declaring what each episode needs means neither mode has to pretend. An
// episode that cannot run says so, rather than being quietly dropped or,
// worse, reported as a pass.
type Capability string

const (
	// CapInProcess: the episode calls into the enforcement packages directly.
	CapInProcess Capability = "in_process"

	// CapHostileDNS: the episode needs to control name resolution.
	CapHostileDNS Capability = "hostile_dns"

	// CapRegistry: the episode revokes a workload through the registry.
	CapRegistry Capability = "registry"

	// CapSinkControl: the episode makes evidence recording fail.
	CapSinkControl Capability = "sink_control"

	// CapNetworkBoundary: the episode is only meaningful where the workload
	// genuinely has no route except the proxy.
	CapNetworkBoundary Capability = "network_boundary"
)

// Episode is one thing a hostile -- or ordinary -- agent tries.
type Episode struct {
	ID     string
	Family Family
	Sev    Severity
	Expect Expectation

	// What the episode is trying to achieve, in the words an incident report
	// would use. This ends up in the findings, so it is written for someone
	// who was not here when it ran.
	Goal string

	// Range names the configuration this episode needs. Episodes that need a
	// revoked workload, an unregistered source or a failing evidence sink
	// cannot share a range with the ordinary ones.
	Range string

	// ExpectReason, when set, is the reason code the evidence record must
	// carry. Getting the outcome right for the wrong reason is worth knowing
	// about: it means the evidence will mislead whoever reads it later.
	ExpectReason string

	// Needs lists capabilities the environment must provide. An episode with
	// none runs anywhere.
	Needs []Capability

	// Run performs the attempt and reports what happened.
	Run func(a *Agent) Attempt
}

// Runnable reports whether an environment offering these capabilities can run
// this episode.
func (e Episode) Runnable(have map[Capability]bool) bool {
	for _, n := range e.Needs {
		if !have[n] {
			return false
		}
	}
	return true
}

// Attempt is the raw outcome of one episode, before it is judged.
type Attempt struct {
	// Reached is true when the agent got a usable response from the
	// destination, whatever the product said about it.
	Reached bool

	// Status is the HTTP status the proxy or destination returned, 0 when the
	// attempt failed before any status was seen.
	Status int

	// ProxyReason is the X-AGW-Reason header from a refusal.
	ProxyReason string

	// Body is what came back, truncated. Used to prove a canary moved.
	Body string

	// Err is the transport-level error, if any.
	Err error

	// Note carries anything the episode wants in the report.
	Note string

	Latency time.Duration
}

// Result is a judged episode.
type Result struct {
	Episode  Episode  `json:"-"`
	ID       string   `json:"id"`
	Family   Family   `json:"family"`
	Severity Severity `json:"severity"`
	Goal     string   `json:"goal"`
	Expect   string   `json:"expect"`

	Passed    bool   `json:"passed"`
	Outcome   string `json:"outcome"`
	Detail    string `json:"detail"`
	ProxyCode string `json:"proxy_reason,omitempty"`

	// EvidenceSeq is the chain sequence of the record covering this episode,
	// 0 when nothing was recorded.
	EvidenceSeq uint64 `json:"evidence_seq,omitempty"`

	// EvidenceReason is what the evidence chain actually said, which is not
	// always what the proxy told the caller.
	EvidenceReason string `json:"evidence_reason,omitempty"`

	LatencyMS int64 `json:"latency_ms"`
}

func (r Result) String() string {
	mark := "FAIL"
	if r.Passed {
		mark = "pass"
	}
	return fmt.Sprintf("[%s] %-34s %-18s %s", mark, r.ID, r.Family, r.Detail)
}
