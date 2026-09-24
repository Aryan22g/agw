package evidence

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// RFC-0009 §2.3 timestamp grammar, exactly:
//
//	YYYY-MM-DDThh:mm:ss[.f{1,9}](Z|±hh:mm)
//
// with an uppercase T and Z, a real calendar date, hh 00-23, mm and ss
// 00-59, and the same ranges for the offset.
//
// Go's own parser is looser in some places (it accepts a comma before the
// fraction, an offset of +24:00, and more than nine fractional digits, which
// it truncates) and stricter in others (lowercase t and z, which RFC 3339
// allows). "Parse it as RFC 3339" therefore meant "parse it as Go does", and a
// third implementation, in JavaScript for the in-browser verifier, would
// have disagreed with this one on exactly those inputs. Every producer writes
// the strict form, so pinning the grammar changes nothing that exists and
// removes the disagreement.
var timestampGrammar = regexp.MustCompile(
	`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$`)

// ValidTimestamp reports whether s matches the RFC-0009 grammar.
func ValidTimestamp(s string) error {
	m := timestampGrammar.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("timestamp %q is not YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)", s)
	}
	n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	year, month, day, hour, min, sec := n(1), n(2), n(3), n(4), n(5), n(6)
	if month < 1 || month > 12 || day < 1 || hour > 23 || min > 59 || sec > 59 {
		return fmt.Errorf("timestamp %q has a field out of range", s)
	}
	// time.Date normalises out-of-range days (Feb 30 -> Mar 2); a date that
	// does not survive the round trip does not exist.
	if time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC).Day() != day {
		return fmt.Errorf("timestamp %q is not a calendar date", s)
	}
	if m[8] != "Z" && (n(9) > 23 || n(10) > 59) {
		return fmt.Errorf("timestamp %q has an offset out of range", s)
	}
	return nil
}

// memberKind is the JSON type a member must have.
type memberKind byte

const (
	kString memberKind = 's'
	kUint   memberKind = 'u' // non-negative integer
	kInt    memberKind = 'i' // integer
	kBool   memberKind = 'b'
	kTime   memberKind = 't' // string matching the timestamp grammar
	kObject memberKind = 'o'
)

var (
	recordKinds = map[string]memberKind{
		"v": kString, "seq": kUint, "eventName": kString, "timestamp": kTime,
		"event": kObject, "prevHash": kString, "hash": kString,
	}
	checkpointKinds = map[string]memberKind{
		"v": kString, "type": kString, "seq": kUint, "hash": kString,
		"count": kUint, "issuedAt": kTime, "keyId": kString, "signature": kString,
	}
	eventKinds = map[string]memberKind{
		"HTTPStatus": kInt, "LatencyMS": kInt, "Federated": kBool,
		"StartedAt": kTime, "FinishedAt": kTime,
		// every other event member is a string
	}
)

// checkKinds enforces RFC-0009's JSON types on present members.
//
// encoding/json is lenient in ways that matter here: it fills null with the
// zero value, and it decodes the string "403" into an integer when asked for
// a json.Number. Two verifiers built on it disagreed with each other on both.
// required says whether null is refused (record and checkpoint members) or
// read as absent (event members, RFC-0009 §2.2).
func checkKinds(obj map[string]json.RawMessage, kinds map[string]memberKind, defaultKind memberKind, required bool) error {
	for name, raw := range obj {
		kind, ok := kinds[name]
		if !ok {
			if defaultKind == 0 {
				continue // unknown member: ignored, not hashed
			}
			kind = defaultKind
		}
		if string(raw) == "null" {
			if required {
				return fmt.Errorf("member %q is null", name)
			}
			continue
		}
		if err := checkKind(raw, kind); err != nil {
			return fmt.Errorf("member %q: %w", name, err)
		}
	}
	return nil
}

var integerGrammar = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func checkKind(raw json.RawMessage, kind memberKind) error {
	switch kind {
	case kString, kTime:
		var s string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
			return fmt.Errorf("must be a string")
		}
		if kind == kTime {
			return ValidTimestamp(s)
		}
	case kUint:
		if !integerGrammar.Match(raw) || raw[0] == '-' {
			return fmt.Errorf("must be a non-negative integer")
		}
		if _, err := strconv.ParseUint(string(raw), 10, 64); err != nil {
			return fmt.Errorf("out of range")
		}
	case kInt:
		if !integerGrammar.Match(raw) {
			return fmt.Errorf("must be an integer")
		}
		if _, err := strconv.ParseInt(string(raw), 10, 64); err != nil {
			return fmt.Errorf("out of range")
		}
	case kBool:
		if string(raw) != "true" && string(raw) != "false" {
			return fmt.Errorf("must be true or false")
		}
	case kObject:
		if len(raw) == 0 || raw[0] != '{' {
			return fmt.Errorf("must be an object")
		}
	}
	return nil
}
