package aat

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

// Check applies the verifier obligations of draft -04 §6.3 that apply to an
// unsigned chain, plus the mandatory fields and enumerations of §3, to a JSON
// Lines file.
//
// It exists to hold the exporter to the draft's own rules rather than to our
// reading of them: an export that fails here is not an AAT chain, whatever
// its field names say. Nonce uniqueness (§6.3 step 7) is checked when nonces
// are present; the exporter writes none.
func Check(r io.Reader) []error {
	var errs []error
	fail := func(line int, format string, a ...any) {
		errs = append(errs, fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, a...)))
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)

	var (
		prev     Record
		prevTime time.Time
		n        int
		nonces   = map[string]bool{}
	)
	for sc.Scan() {
		raw := bytes.TrimSpace(sc.Bytes())
		if len(raw) == 0 {
			continue
		}
		n++
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&rec); err != nil {
			fail(n, "not a JSON object: %v", err)
			continue
		}

		for _, f := range mandatory {
			if _, ok := rec[f]; !ok {
				fail(n, "mandatory field %q is missing", f)
			}
		}
		checkEnum(rec, "action_type", actionTypes, n, fail)
		checkEnum(rec, "outcome", outcomes, n, fail)
		checkEnum(rec, "trust_level", trustLevels, n, fail)
		checkEnum(rec, "record_phase", phases, n, fail)
		for _, f := range []string{"record_id", "session_id"} {
			if s, _ := rec[f].(string); !uuidV4.MatchString(s) {
				fail(n, "%s %q is not a UUIDv4", f, s)
			}
		}
		if s, _ := rec["agent_version"].(string); !semver.MatchString(s) {
			fail(n, "agent_version %q is not SemVer", s)
		}

		ts, _ := rec["timestamp"].(string)
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			fail(n, "timestamp %q is not RFC 3339", ts)
		}

		if n == 1 {
			// §6.3 step 1, and the genesis rule.
			if rec["parent_record_id"] != nil || rec["prev_hash"] != nil {
				fail(n, "genesis record must have null parent_record_id and prev_hash")
			}
			detail, _ := rec["action_detail"].(map[string]any)
			if rec["action_type"] != "lifecycle" || detail["event"] != "session_start" {
				fail(n, "genesis record must be lifecycle/session_start")
			}
		} else {
			// §6.3 step 2: prev_hash covers the previous record.
			want, err := recordHash(prev)
			if err != nil {
				fail(n, "cannot hash previous record: %v", err)
			} else if rec["prev_hash"] != want {
				fail(n, "prev_hash does not match the previous record")
			}
			// §6.3 step 5.
			if rec["parent_record_id"] != prev["record_id"] {
				fail(n, "parent_record_id does not name the previous record")
			}
			// §6.3 step 4.
			if err == nil && t.Before(prevTime) {
				fail(n, "timestamp goes backwards")
			}
			if rec["session_id"] != prev["session_id"] {
				fail(n, "session_id changes within the chain")
			}
		}

		// §6.3 step 6 / §4.2: a denied decision must be pre-execution.
		if rec["action_type"] == "decision" && rec["outcome"] == "denied" && rec["record_phase"] != "pre_execution" {
			fail(n, "a denied decision must have record_phase pre_execution")
		}
		// §6.3 step 7.
		if nonce, ok := rec["nonce"].(string); ok {
			if nonces[nonce] {
				fail(n, "nonce reused within the session")
			}
			nonces[nonce] = true
		}

		prev, prevTime = rec, t
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	if n == 0 {
		errs = append(errs, fmt.Errorf("no records"))
	}
	return errs
}

var (
	mandatory = []string{"record_id", "timestamp", "agent_id", "agent_version", "session_id",
		"action_type", "action_detail", "outcome", "trust_level", "parent_record_id", "prev_hash", "record_phase"}
	actionTypes = []string{"tool_call", "tool_response", "decision", "delegation", "escalation", "error", "lifecycle"}
	outcomes    = []string{"success", "failure", "timeout", "denied", "escalated"}
	trustLevels = []string{"L0", "L1", "L2", "L3", "L4"}
	phases      = []string{"pre_execution", "post_execution", "concurrent"}

	uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
)

func checkEnum(rec Record, field string, allowed []string, line int, fail func(int, string, ...any)) {
	v, _ := rec[field].(string)
	for _, a := range allowed {
		if v == a {
			return
		}
	}
	fail(line, "%s %q is not one of %v", field, v, allowed)
}
