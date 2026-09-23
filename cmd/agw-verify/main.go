// Command agw-verify checks an agw evidence log.
//
// It is a second, independent implementation of RFC-0009, written from the
// specification rather than from the reference code, and it imports only the
// Go standard library -- a test fails if that ever changes. Two things follow.
//
// A security team can read the whole of it before running it in an
// air-gapped room: it is one file, it opens no sockets, and it depends on
// nothing this repository could have tampered with.
//
// And it is evidence that the specification is complete. If a verifier built
// from the text alone agrees with the reference implementation on every
// conformance vector, the format is defined by the document, not by whatever
// our code happens to do.
//
//	agw-verify [--key PUB] [--anchor KEPT] [--json] EVIDENCE.jsonl
//
// Exit status: 0 verified, 2 did not verify, 1 could not run.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	versionV2 = "agw-evidence-v2"
	versionV1 = "agw-evidence-v1"
)

// genesis is sixty-four ASCII zeros (RFC-0009 §2.1).
var genesis = strings.Repeat("0", 64)

// Problem is one finding, with the sequence number RFC-0009 §6.4 assigns it.
type Problem struct {
	Kind   string `json:"kind"`
	Seq    uint64 `json:"seq"`
	Detail string `json:"detail"`
}

// Result is what RFC-0009 §6.4 requires a verifier to report.
type Result struct {
	Intact            bool      `json:"intact"`
	Records           uint64    `json:"records"`
	Checkpoints       uint64    `json:"checkpoints"`
	HeadSeq           uint64    `json:"head_seq"`
	SignedThrough     uint64    `json:"signed_through"`
	UnanchoredRecords uint64    `json:"unanchored_records"`
	KeyGiven          bool      `json:"key_given"`
	Problems          []Problem `json:"problems"`
}

// ---------------------------------------------------------------- encoding

// timestampRE is the RFC-0009 §2.3 grammar. Ranges and the calendar are
// checked separately in ts.
var timestampRE = regexp.MustCompile(
	`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$`)

// ts is TS(t) from RFC-0009 §2.3: check the grammar, convert to UTC, format
// with nanoseconds and trailing zeros removed, no fraction if it is zero.
func ts(s string) (string, error) {
	m := timestampRE.FindStringSubmatch(s)
	if m == nil {
		return "", fmt.Errorf("timestamp %q does not match the RFC-0009 grammar", s)
	}
	num := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
	y, mo, d, h, mi, se := num(1), num(2), num(3), num(4), num(5), num(6)
	if mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59 {
		return "", fmt.Errorf("timestamp %q has a field out of range", s)
	}
	if time.Date(y, time.Month(mo), d, 0, 0, 0, 0, time.UTC).Day() != d {
		return "", fmt.Errorf("timestamp %q is not a calendar date", s)
	}
	offset := 0
	if m[8] != "Z" {
		oh, om := num(9), num(10)
		if oh > 23 || om > 59 {
			return "", fmt.Errorf("timestamp %q has an offset out of range", s)
		}
		offset = oh*3600 + om*60
		if m[8][0] == '-' {
			offset = -offset
		}
	}
	nanos := 0
	if m[7] != "" {
		frac := m[7][1:] + strings.Repeat("0", 9-len(m[7][1:]))
		nanos, _ = strconv.Atoi(frac)
	}
	t := time.Date(y, time.Month(mo), d, h, mi, se, nanos, time.UTC).Add(-time.Duration(offset) * time.Second)
	out := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d",
		t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
	if ns := t.Nanosecond(); ns != 0 {
		out += "." + strings.TrimRight(fmt.Sprintf("%09d", ns), "0")
	}
	return out + "Z", nil
}

// field is F(s): the byte length, a colon, the bytes.
func field(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// rawRecord mirrors RFC-0009 §2.1 with every member kept as raw JSON, so the
// type of each value can be checked explicitly rather than coerced.
type rawRecord struct {
	V         *string                    `json:"v"`
	Seq       json.Number                `json:"seq"`
	EventName *string                    `json:"eventName"`
	Timestamp *string                    `json:"timestamp"`
	Event     map[string]json.RawMessage `json:"event"`
	PrevHash  *string                    `json:"prevHash"`
	Hash      *string                    `json:"hash"`
}

type record struct {
	v, eventName, timestamp, prevHash, hash string
	seq                                     uint64
	event                                   map[string]json.RawMessage
}

// eventFields is RFC-0009 §2.2 in hash order, with each member's JSON type.
var eventFields = []struct{ name, kind string }{
	{"EventID", "s"}, {"TenantID", "s"}, {"AgentID", "s"}, {"KeyID", "s"},
	{"DecisionID", "s"}, {"RequestID", "s"}, {"TraceID", "s"},
	{"RouteID", "s"}, {"Action", "s"}, {"ResourceType", "s"}, {"ResourceID", "s"},
	{"BackendID", "s"}, {"Decision", "s"}, {"ReasonCode", "s"},
	{"HTTPStatus", "i"}, {"SourceIP", "s"}, {"UserAgent", "s"},
	{"StartedAt", "t"}, {"FinishedAt", "t"}, {"LatencyMS", "i"},
	// v2 only:
	{"SourceTenant", "s"}, {"Federated", "b"}, {"TrustGrant", "s"}, {"Risk", "s"}, {"Producer", "s"},
}

const v1FieldCount = 20

var integerRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// eventValue renders one event member for the hash, applying the zero-value
// rule of RFC-0009 §2.2 when it is absent.
func eventValue(raw json.RawMessage, kind string) (string, error) {
	missing := len(raw) == 0 || string(raw) == "null"
	switch kind {
	case "s":
		if missing {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", errors.New("expected a string")
		}
		return s, nil
	case "i":
		if missing {
			return "0", nil
		}
		// An integer is a JSON number with no fraction or exponent. A
		// json.Number would also accept the STRING "403", which the
		// specification does not.
		if !integerRE.Match(raw) {
			return "", errors.New("expected an integer")
		}
		i, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return "", errors.New("expected an integer")
		}
		return strconv.FormatInt(i, 10), nil
	case "b":
		if missing {
			return "false", nil
		}
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			return "", errors.New("expected a boolean")
		}
		return strconv.FormatBool(b), nil
	case "t":
		if missing {
			return "0001-01-01T00:00:00Z", nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return "", errors.New("expected a timestamp string")
		}
		return ts(s)
	}
	return "", fmt.Errorf("unknown field kind %q", kind)
}

// hashInput is H(r) from RFC-0009 §3.
func hashInput(r record) (string, error) {
	var b strings.Builder
	b.WriteString(r.v)
	b.WriteByte('\n')
	field(&b, strconv.FormatUint(r.seq, 10))
	field(&b, r.prevHash)
	field(&b, r.eventName)
	t, err := ts(r.timestamp)
	if err != nil {
		return "", fmt.Errorf("timestamp: %w", err)
	}
	field(&b, t)

	n := len(eventFields)
	if r.v == versionV1 {
		n = v1FieldCount
	}
	for _, f := range eventFields[:n] {
		v, err := eventValue(r.event[f.name], f.kind)
		if err != nil {
			return "", fmt.Errorf("event.%s: %w", f.name, err)
		}
		field(&b, v)
	}
	return b.String(), nil
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------- checkpoints

type checkpoint struct {
	V         string      `json:"v"`
	Type      string      `json:"type"`
	Seq       json.Number `json:"seq"`
	Hash      string      `json:"hash"`
	Count     json.Number `json:"count"`
	IssuedAt  string      `json:"issuedAt"`
	KeyID     string      `json:"keyId"`
	Signature string      `json:"signature"`

	seq, count uint64
}

// signingInput is C(c) from RFC-0009 §4.2.
func signingInput(c checkpoint) (string, error) {
	var b strings.Builder
	b.WriteString(versionV2 + "/checkpoint\n")
	field(&b, strconv.FormatUint(c.seq, 10))
	field(&b, c.Hash)
	field(&b, strconv.FormatUint(c.count, 10))
	t, err := ts(c.IssuedAt)
	if err != nil {
		return "", err
	}
	field(&b, t)
	field(&b, c.KeyID)
	return b.String(), nil
}

func signatureValid(pub ed25519.PublicKey, c checkpoint) bool {
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := signingInput(c)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(msg), sig)
}

func parseCheckpoint(raw []byte) (checkpoint, error) {
	var c checkpoint
	// Every checkpoint member is required (RFC-0009 §4.1).
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return c, err
	}
	for _, k := range []string{"v", "type", "seq", "hash", "count", "issuedAt", "keyId", "signature"} {
		if _, ok := present[k]; !ok {
			return c, fmt.Errorf("checkpoint is missing %q", k)
		}
	}
	if err := exactNames(present, []string{"v", "type", "seq", "hash", "count", "issuedAt", "keyId", "signature"}); err != nil {
		return c, err
	}
	for _, k := range []string{"v", "type", "hash", "issuedAt", "keyId", "signature"} {
		if raw := present[k]; len(raw) == 0 || raw[0] != '"' {
			return c, fmt.Errorf("checkpoint %q must be a string", k)
		}
	}
	for _, k := range []string{"seq", "count"} {
		if raw := present[k]; !integerRE.Match(raw) || raw[0] == '-' {
			return c, fmt.Errorf("checkpoint %q must be a non-negative integer", k)
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var err error
	if c.seq, err = strconv.ParseUint(c.Seq.String(), 10, 64); err != nil {
		return c, errors.New("seq is not a non-negative integer")
	}
	if c.count, err = strconv.ParseUint(c.Count.String(), 10, 64); err != nil {
		return c, errors.New("count is not a non-negative integer")
	}
	if _, err := ts(c.IssuedAt); err != nil {
		return c, errors.New("issuedAt is not RFC 3339")
	}
	return c, nil
}

// ---------------------------------------------------------------- I-JSON

// noDuplicates enforces RFC-0009 §1: no object at any depth repeats a
// member name.
func noDuplicates(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return walk(d)
}

func walk(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if seen[k] {
				return fmt.Errorf("duplicate member name %q", k)
			}
			seen[k] = true
			if err := walk(d); err != nil {
				return err
			}
		}
		_, err = d.Token() // '}'
		return err
	case '[':
		for d.More() {
			if err := walk(d); err != nil {
				return err
			}
		}
		_, err = d.Token() // ']'
		return err
	}
	return nil
}

// exactNames enforces RFC-0009 §1's case rule: a member whose name equals a
// defined name except for letter case is malformed. Many JSON libraries match
// names case-insensitively, so such a member would be read as the defined one
// by some tools and ignored by others.
func exactNames(obj map[string]json.RawMessage, defined []string) error {
	for k := range obj {
		for _, d := range defined {
			if k != d && strings.EqualFold(k, d) {
				return fmt.Errorf("member %q differs from %q only by case", k, d)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- lines

type lineKind int

const (
	lineRecord lineKind = iota
	lineCheckpoint
)

// classify decodes one line, enforcing the structural rules of §1 and the
// member types of §2 and §4. Any failure here is `malformed`.
func classify(raw []byte) (lineKind, record, checkpoint, error) {
	if err := noDuplicates(raw); err != nil {
		return 0, record{}, checkpoint{}, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return 0, record{}, checkpoint{}, errors.New("not a JSON object")
	}
	var typ string
	if t, ok := probe["type"]; ok {
		_ = json.Unmarshal(t, &typ)
	}
	if typ == "checkpoint" {
		c, err := parseCheckpoint(raw)
		return lineCheckpoint, record{}, c, err
	}

	var rr rawRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&rr); err != nil {
		return 0, record{}, checkpoint{}, fmt.Errorf("record: %v", err)
	}
	// Every record member is required (RFC-0009 §2.1); only event members
	// may be absent.
	if rr.V == nil || rr.Seq == "" || rr.EventName == nil || rr.Timestamp == nil ||
		rr.Event == nil || rr.PrevHash == nil || rr.Hash == nil {
		return 0, record{}, checkpoint{}, errors.New("record is missing a required member")
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(raw, &top)
	if err := exactNames(top, []string{"v", "seq", "eventName", "timestamp", "event", "prevHash", "hash", "type"}); err != nil {
		return 0, record{}, checkpoint{}, err
	}
	names := make([]string, len(eventFields))
	for i, f := range eventFields {
		names[i] = f.name
	}
	if err := exactNames(rr.Event, names); err != nil {
		return 0, record{}, checkpoint{}, err
	}
	r := record{event: rr.Event}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	r.v, r.eventName, r.timestamp = deref(rr.V), deref(rr.EventName), deref(rr.Timestamp)
	r.prevHash, r.hash = deref(rr.PrevHash), deref(rr.Hash)
	var err error
	if raw := top["seq"]; !integerRE.Match(raw) || raw[0] == '-' {
		return 0, record{}, checkpoint{}, errors.New("seq is not a non-negative integer")
	}
	if r.seq, err = strconv.ParseUint(rr.Seq.String(), 10, 64); err != nil {
		return 0, record{}, checkpoint{}, errors.New("seq is out of range")
	}
	if raw := top["event"]; len(raw) == 0 || raw[0] != '{' {
		return 0, record{}, checkpoint{}, errors.New("event must be an object")
	}
	if _, err := ts(r.timestamp); err != nil {
		return 0, record{}, checkpoint{}, errors.New("timestamp is not RFC 3339")
	}
	// Check every event member's type now, so a wrongly typed member is
	// `malformed` rather than a hash mismatch that points nowhere useful.
	for _, f := range eventFields {
		if _, err := eventValue(r.event[f.name], f.kind); err != nil {
			return 0, record{}, checkpoint{}, fmt.Errorf("event.%s: %v", f.name, err)
		}
	}
	return lineRecord, r, checkpoint{}, nil
}

// ---------------------------------------------------------------- verify

// Verify is RFC-0009 §6.
func Verify(log io.Reader, pub ed25519.PublicKey, anchor *checkpoint) (*Result, error) {
	var (
		res      = &Result{Intact: true, KeyGiven: pub != nil, Problems: []Problem{}}
		expected = genesis
		lastSeq  uint64
		seen     = map[uint64]string{}
	)
	fail := func(kind string, seq uint64, detail string) {
		res.Problems = append(res.Problems, Problem{kind, seq, detail})
		res.Intact = false
	}

	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		raw := bytes.Trim(sc.Bytes(), " \t\r\n\v\f")
		if len(raw) == 0 {
			continue
		}

		kind, r, c, err := classify(raw)
		if err != nil {
			fail("malformed", lastSeq+1, err.Error())
			continue
		}

		if kind == lineCheckpoint {
			res.Checkpoints++
			seen[c.seq] = c.Hash
			switch {
			case c.V != versionV2:
				fail("checkpoint", c.seq, fmt.Sprintf("declares version %q", c.V))
			case c.seq != lastSeq:
				fail("checkpoint", c.seq, fmt.Sprintf("commits to seq %d but the chain is at %d", c.seq, lastSeq))
			case c.Hash != expected:
				fail("checkpoint", c.seq, "commits to a head that is not the chain's head")
			case pub != nil && !signatureValid(pub, c):
				fail("checkpoint", c.seq, "signature does not verify under the given key")
			default:
				if pub != nil {
					res.SignedThrough = c.seq
				}
			}
			continue
		}

		switch r.v {
		case versionV2:
		case versionV1:
			// Reported, but does not clear intact (§6.2 step 3.1).
			res.Problems = append(res.Problems, Problem{"superseded_format", r.seq,
				"v1 record: SourceTenant, Federated, TrustGrant, Risk and Producer are not protected"})
		default:
			fail("version", r.seq, fmt.Sprintf("declares version %q", r.v))
			continue
		}

		if r.seq != lastSeq+1 {
			fail("sequence", r.seq, fmt.Sprintf("expected seq %d", lastSeq+1))
		}
		if r.prevHash != expected {
			fail("chain", r.seq, "prevHash does not match the previous record's hash")
		}
		in, err := hashInput(r)
		if err != nil || sha256hex(in) != r.hash {
			fail("content", r.seq, "the record's contents do not hash to its hash")
		}

		res.Records++
		lastSeq = r.seq
		expected = r.hash
		res.HeadSeq = r.seq
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	if anchor != nil && pub != nil {
		if anchor.V != versionV2 || !signatureValid(pub, *anchor) {
			fail("anchor_invalid", anchor.seq, "the anchor is not a checkpoint signed by the given key")
			anchor = nil
		}
	}
	if anchor != nil {
		got, ok := seen[anchor.seq]
		switch {
		case res.HeadSeq < anchor.seq:
			fail("rollback", res.HeadSeq, fmt.Sprintf("log ends at %d; the anchor covers %d", res.HeadSeq, anchor.seq))
		case !ok:
			fail("missing_anchor", anchor.seq, "the log contains no checkpoint at the anchor's seq")
		case got != anchor.Hash:
			fail("forked", anchor.seq, "the log's checkpoint and the anchor commit to different heads")
		}
	}

	if pub != nil {
		if res.HeadSeq > res.SignedThrough { // saturating, RFC-0009 §6.3
			res.UnanchoredRecords = res.HeadSeq - res.SignedThrough
		}
		if res.Checkpoints == 0 && res.Records > 0 {
			fail("unanchored", res.HeadSeq, "no checkpoint: nothing in this log is pinned by a signature")
		}
	}
	return res, nil
}

// ---------------------------------------------------------------- CLI

func loadKey(v string) (ed25519.PublicKey, error) {
	if v == "" {
		return nil, nil
	}
	s := v
	if b, err := os.ReadFile(v); err == nil {
		s = string(b)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("--key: not a readable key file or a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func loadAnchor(path string) (*checkpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var last *checkpoint
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		kind, _, c, err := classify(line)
		if err == nil && kind == lineCheckpoint {
			cc := c
			last = &cc
		}
	}
	if last == nil {
		return nil, fmt.Errorf("%s contains no checkpoint", path)
	}
	return last, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("agw-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	key := fs.String("key", "", "checkpoint public key: a file, or the base64 key")
	anchorPath := fs.String("anchor", "", "a checkpoint kept from an earlier reading of this log")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: agw-verify [--key PUB] [--anchor KEPT] [--json] EVIDENCE.jsonl")
		fs.PrintDefaults()
	}

	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return 1
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		fs.Usage()
		return 1
	}

	pub, err := loadKey(*key)
	if err != nil {
		fmt.Fprintln(stderr, "agw-verify:", err)
		return 1
	}
	var anchor *checkpoint
	if *anchorPath != "" {
		if anchor, err = loadAnchor(*anchorPath); err != nil {
			fmt.Fprintln(stderr, "agw-verify:", err)
			return 1
		}
	}
	f, err := os.Open(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "agw-verify:", err)
		return 1
	}
	defer f.Close()

	res, err := Verify(f, pub, anchor)
	if err != nil {
		fmt.Fprintln(stderr, "agw-verify:", err)
		return 1
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Fprintf(stdout, "%s: %d records, %d checkpoints, head seq %d\n",
			pos[0], res.Records, res.Checkpoints, res.HeadSeq)
		for _, p := range res.Problems {
			fmt.Fprintf(stdout, "  seq %-8d %-18s %s\n", p.Seq, p.Kind, p.Detail)
		}
		switch {
		case !res.Intact:
			fmt.Fprintln(stdout, "NOT VERIFIED")
		case res.Records == 0:
			// RFC-0009 §6.4: nothing was checked, and an empty log is also
			// what deleting every record leaves. Only --anchor tells them apart.
			fmt.Fprintln(stdout, "EMPTY (no records, nothing to verify; an empty log is also what deleting every record produces, which only --anchor detects)")
		case pub == nil:
			fmt.Fprintln(stdout, "VERIFIED (chain only: no key given, signatures not checked)")
		case res.UnanchoredRecords > 0:
			fmt.Fprintf(stdout, "VERIFIED THROUGH seq %d (%d later record(s) are not signed and could be removed undetectably)\n",
				res.SignedThrough, res.UnanchoredRecords)
		default:
			fmt.Fprintln(stdout, "VERIFIED")
		}
	}
	if !res.Intact {
		return 2
	}
	return 0
}
