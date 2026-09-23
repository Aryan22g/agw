// Package aat converts an agw evidence chain into records in the format of
// the IETF Agent Audit Trail Internet-Draft, draft-sharif-agent-audit-trail-04.
//
// The aim is to conform to that draft rather than compete with it. The two formats are different designs --
// JCS over whole records versus a fixed length-prefixed field set, per-record
// ES256 versus periodic Ed25519 checkpoints -- so conformance is a
// conversion, and this is it. docs/aat-mapping.md explains every field.
//
// Two properties are deliberate.
//
// The source chain is verified before anything is converted. Converting a
// log that does not verify would launder tampering into a fresh, internally
// consistent AAT chain that says nothing about what was altered.
//
// The output is unsigned. Integrity comes from the Ed25519 checkpoints over
// the source chain, which travels with the export; the draft's per-record
// signatures would need a P-256 or ML-DSA key and, in -04, its description of
// what prev_hash covers for a signed record is ambiguous (see RFC-0009
// Appendix A). An unsigned export is unaffected by that ambiguity.
package aat

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/pkg/ags1/jcs"
)

// DraftVersion is the revision of the draft this mapping follows.
const DraftVersion = "draft-sharif-agent-audit-trail-04"

// Options configures a conversion.
type Options struct {
	// AgentVersion fills the draft's mandatory agent_version (SemVer). The
	// evidence chain does not record the agent's version, so it cannot be
	// derived; 0.0.0 says "unknown" in the only form SemVer allows.
	AgentVersion string

	// Source names the evidence file, for the genesis record.
	Source string
}

// Record is one AAT record. A map rather than a struct: JCS canonicalises
// member order anyway, and optional members must be absent rather than
// empty, which a map expresses directly.
type Record map[string]any

// Convert verifies an evidence chain and converts it.
//
// records and the verification result come from the caller, which has
// already read the file; Convert refuses when the result is not intact.
func Convert(records []audit.Record, verified *audit.VerifyResult, opts Options) ([]Record, error) {
	if verified == nil || !verified.Intact {
		return nil, fmt.Errorf("aat: refusing to convert a chain that does not verify; " +
			"converting it would produce a clean-looking AAT chain that hides the tampering")
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("aat: the chain has no records")
	}
	if opts.AgentVersion == "" {
		opts.AgentVersion = "0.0.0"
	}

	// The session is the chain. Deriving its id from the first record's hash
	// makes re-exporting the same chain produce the same session.
	session := uuidFrom("session", records[0].Hash)

	out := make([]Record, 0, len(records)+1)

	// §3: the first record of a session must be lifecycle/session_start with
	// null links. The evidence chain has no such record, so one is written
	// describing the export itself.
	first := records[0]
	genesis := Record{
		"record_id":           uuidFrom("genesis", first.Hash),
		"timestamp":           rfc3339(first.Timestamp),
		"agent_id":            agentURI(first.Event),
		"agent_version":       opts.AgentVersion,
		"session_id":          session,
		"action_type":         "lifecycle",
		"action_detail":       map[string]any{"event": "session_start", "trigger": "agw_evidence_export", "agw_source": opts.Source, "agw_first_seq": first.Seq, "agw_first_hash": first.Hash},
		"outcome":             "success",
		"trust_level":         trustLevel(first.Event),
		"parent_record_id":    nil,
		"prev_hash":           nil,
		"record_phase":        "concurrent",
		"recording_component": "urn:agw:exporter:" + DraftVersion,
	}
	out = append(out, genesis)

	for _, r := range records {
		out = append(out, convertOne(r, session, opts))
	}

	// Link: parent_record_id and prev_hash = hex(SHA-256(JCS(previous))).
	for i := 1; i < len(out); i++ {
		h, err := recordHash(out[i-1])
		if err != nil {
			return nil, err
		}
		out[i]["parent_record_id"] = out[i-1]["record_id"]
		out[i]["prev_hash"] = h
	}
	return out, nil
}

func convertOne(r audit.Record, session string, opts Options) Record {
	e := r.Event
	actionType, detail := actionOf(r)

	// Every AAT record carries a pointer back to the evidence record it came
	// from, so an auditor can go from either file to the other and check
	// that the signed original says what the conversion says.
	detail["agw_seq"] = r.Seq
	detail["agw_hash"] = r.Hash
	detail["agw_event"] = r.EventName
	if e.ResourceID != "" {
		detail["agw_resource"] = e.ResourceID
	}
	if e.ReasonCode != "" && e.ReasonCode != "allowed" {
		detail["agw_reason"] = e.ReasonCode
	}
	if e.Decision == "would_deny" || e.Decision == "would_allow" || e.Decision == "not_evaluable" {
		detail["agw_shadow_verdict"] = e.Decision
	}

	rec := Record{
		"record_id":     uuidFrom("record", r.Hash),
		"timestamp":     rfc3339(r.Timestamp),
		"agent_id":      agentURI(e),
		"agent_version": opts.AgentVersion,
		"session_id":    session,
		"action_type":   actionType,
		"action_detail": detail,
		"outcome":       outcomeOf(e.Decision),
		"trust_level":   trustLevel(e),
		"record_phase":  phaseOf(r),
	}
	if e.Producer != "" {
		// The draft makes this mandatory when something other than the agent
		// wrote the record -- which, for an enforcement point the agent
		// cannot bypass, is the entire point.
		rec["recording_component"] = "urn:agw:producer:" + e.Producer
	}
	if e.LatencyMS > 0 {
		rec["latency_ms"] = e.LatencyMS
	}
	if rec["outcome"] == "denied" {
		rec["deny_reasons"] = []string{denyReason(e.ReasonCode)}
	}
	if e.Risk != "" {
		if score, ok := riskScore[e.Risk]; ok {
			rec["risk_score"] = score
		}
	}
	return rec
}

// actionOf chooses the draft's action_type and builds its required detail.
func actionOf(r audit.Record) (string, map[string]any) {
	e := r.Event
	switch {
	case strings.HasPrefix(r.EventName, "confine.workload."):
		// Registration and revocation are the workload's lifecycle.
		ev := strings.TrimPrefix(r.EventName, "confine.workload.")
		return "lifecycle", map[string]any{"event": "workload_" + ev, "trigger": e.ReasonCode}

	case e.Producer == audit.ProducerRecorder:
		// Self-reported activity. tool_call requires parameters_hash; the
		// chain holds no parameters, so this is the hash of what it does hold
		// about the call, and the mapping document says so.
		name := strings.TrimPrefix(e.Action, "tool.")
		return "tool_call", map[string]any{
			"tool_name":       name,
			"parameters_hash": sha256Hex("agw-aat-params\n" + e.Action + "\n" + e.ResourceID),
		}

	default:
		// Every enforced record is a decision made before the action.
		kind := "authorization"
		switch {
		case strings.HasPrefix(e.Producer, "enforced:confine"):
			kind = "egress_authorization"
		case e.Producer == audit.ProducerMCP:
			kind = "tool_authorization"
		case e.Producer == audit.ProducerGateway:
			kind = "request_authorization"
		}
		d := map[string]any{"decision_type": kind}
		if e.RouteID != "" {
			d["policy_ref"] = e.RouteID
		}
		d["agw_action"] = e.Action
		return "decision", d
	}
}

// outcomeOf maps a decision to the draft's outcome vocabulary. Shadow-mode
// verdicts describe what enforcement WOULD have done; nothing was blocked,
// so the action's outcome is success and the verdict rides in action_detail.
func outcomeOf(decision string) string {
	switch decision {
	case "deny":
		return "denied"
	case "error":
		return "failure"
	default:
		return "success"
	}
}

// phaseOf: enforcement records are written before the action (the draft
// requires pre_execution for every denied decision); a connection-closed
// record and recorder observations are written after it.
func phaseOf(r audit.Record) string {
	switch {
	case r.EventName == "confine.egress.closed", r.Event.Producer == audit.ProducerRecorder:
		return "post_execution"
	case strings.HasPrefix(r.EventName, "confine.workload."):
		return "concurrent"
	default:
		return "pre_execution"
	}
}

// trustLevel maps onto the draft's L0-L4, which grades the agent's own
// credential. Identity by provenance -- the confined agent deliberately holds
// no credential -- has no place on that scale and is recorded as L0, with
// recording_component carrying the enforcement point's independence. RFC-0009
// Appendix A raises this with the draft.
func trustLevel(e audit.GatewayEvent) string {
	switch {
	case e.Producer == audit.ProducerGateway && e.Federated:
		return "L3" // both organisations' keys verified under a trust grant
	case e.Producer == audit.ProducerGateway && e.KeyID != "":
		return "L2" // a registered key, issued through the control plane
	default:
		return "L0"
	}
}

// denyReason uses the draft's registered codes where the meaning genuinely
// matches, and an implementation-prefixed code otherwise, as the draft asks.
func denyReason(reason string) string {
	switch reason {
	case "workload_revoked", "credential_revoked":
		return "AGENT_REVOKED"
	case "replay_detected":
		return "REPLAY_DETECTED"
	case "request_expired", "request_not_yet_valid":
		return "TIMESTAMP_STALE"
	case "policy_denied", "no_policy_for_agent", "not_in_allowlist", "outside_trust_grant":
		return "CAPABILITY_NOT_GRANTED"
	case "route_unknown":
		return "ACTION_UNKNOWN"
	case "":
		return "AGW_DENIED"
	}
	return "AGW_" + strings.ToUpper(reason)
}

var riskScore = map[string]float64{"read": 0.1, "write": 0.4, "privileged": 0.7, "destructive": 1.0}

// agentURI builds a stable URI for the agent. tenant and agent are escaped
// separately so neither can smuggle a separator into the other.
func agentURI(e audit.GatewayEvent) string {
	agent := e.AgentID
	if agent == "" {
		agent = "unattributed"
	}
	if e.TenantID == "" {
		return "urn:agw:agent:" + url.PathEscape(agent)
	}
	return "urn:agw:agent:" + url.PathEscape(e.TenantID) + ":" + url.PathEscape(agent)
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// uuidFrom derives a UUID shaped as version 4 from a hash.
//
// The draft asks for UUIDv4. Its bits are meant to be unpredictable, which a
// SHA-256 output is, and deriving them rather than drawing them means
// re-exporting a chain produces byte-identical output -- which is what lets
// two parties compare exports at all.
func uuidFrom(domain, h string) string {
	sum := sha256.Sum256([]byte("agw-aat-uuid\n" + domain + "\n" + h))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// recordHash is hex(SHA-256(JCS(record))) with signature-value fields and
// any batch object removed. None are present in an unsigned export, so the
// two readings of -04 agree here.
func recordHash(r Record) (string, error) {
	clean := make(Record, len(r))
	for k, v := range r {
		switch k {
		case "signature", "signature_classical", "batch":
			continue
		}
		clean[k] = v
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return "", err
	}
	canon, err := jcs.Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("aat: canonicalise: %w", err)
	}
	return sha256Hex(string(canon)), nil
}

// Marshal renders records as JSON Lines, genesis first, as the draft's
// primary storage format requires.
func Marshal(records []Record) ([]byte, error) {
	var b strings.Builder
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}
