package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The RFC-0009 conformance corpus.
//
// Vectors are BUILT by the product's writer (Link, SignCheckpoint) and then
// edited by hand into the negative cases, but their EXPECTED results are
// written out below from the specification, not obtained by running Verify.
// A corpus whose expectations came from the implementation would certify
// whatever the implementation happens to do, bugs included. The test then
// requires Verify to agree with the specification -- and cmd/agw-verify,
// written separately from the text, is held to the same file.

var updateCorpus = flag.Bool("update-corpus", false, "rewrite conformance/evidence/agw-evidence-v2.json")

const corpusPath = "../../conformance/evidence/agw-evidence-v2.json"

// corpusSeed derives the test key. It is published so anyone can regenerate
// the corpus, and it is useless for anything else by construction.
const corpusSeed = "agw-evidence-v2 conformance test key -- public, never use for anything real"

type corpusProblem struct {
	Kind string `json:"kind"`
	Seq  uint64 `json:"seq"`
}

type corpusExpect struct {
	Intact            bool            `json:"intact"`
	Records           uint64          `json:"records"`
	Checkpoints       uint64          `json:"checkpoints"`
	HeadSeq           uint64          `json:"head_seq"`
	SignedThrough     uint64          `json:"signed_through"`
	UnanchoredRecords uint64          `json:"unanchored_records"`
	Problems          []corpusProblem `json:"problems"`
}

type corpusVector struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Log         string `json:"log"`
	// Key is "test" for the corpus key, "" for chain-only verification.
	Key    string          `json:"key"`
	Anchor json.RawMessage `json:"anchor,omitempty"`
	Expect corpusExpect    `json:"expect"`
}

type hashVector struct {
	Name           string `json:"name"`
	Record         string `json:"record"`
	CanonicalInput string `json:"canonical_input"`
	Hash           string `json:"hash"`
}

type corpus struct {
	Spec          string         `json:"spec"`
	Version       string         `json:"version"`
	KeySeed       string         `json:"key_seed"`
	PublicKey     string         `json:"public_key"`
	Note          string         `json:"note"`
	HashVectors   []hashVector   `json:"hash_vectors"`
	VerifyVectors []corpusVector `json:"verify_vectors"`
}

func corpusKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(corpusSeed))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

var t0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func ev(i int, decision, reason, resource string) GatewayEvent {
	return GatewayEvent{
		EventID: "", TenantID: "acme", AgentID: "agent-eval-01", KeyID: "sha256:img",
		DecisionID: "dec_" + strings.Repeat(string(rune('a'+i)), 8),
		Action:     "net.connect", ResourceType: "host", ResourceID: resource,
		Decision: decision, ReasonCode: reason, HTTPStatus: 403,
		SourceIP: "10.0.0.20", Producer: ProducerConfineProxy,
		StartedAt:  t0.Add(time.Duration(i) * time.Second),
		FinishedAt: t0.Add(time.Duration(i)*time.Second + 1500*time.Microsecond),
		LatencyMS:  1,
	}
}

var destinations = []string{
	"pypi.org:443", "169.254.169.254:80", "paste.example:443",
	"files.pythonhosted.org:443", "evil.example:443", "pypi.org:443",
}

// chainLines builds n records with a checkpoint after each seq in cps.
func chainLines(t *testing.T, n int, cps ...uint64) [][]byte {
	t.Helper()
	_, priv := corpusKey()
	isCP := map[uint64]bool{}
	for _, c := range cps {
		isCP[c] = true
	}
	var out [][]byte
	prev := GenesisHash
	for i := 1; i <= n; i++ {
		decision, reason := "deny", "not_in_allowlist"
		if i%3 == 1 {
			decision, reason = "allow", "allowed"
		}
		if i == 2 {
			reason = "metadata_endpoint"
		}
		r := Link(Record{
			EventName: "confine.egress." + map[string]string{"allow": "allowed", "deny": "denied"}[decision],
			Timestamp: t0.Add(time.Duration(i)*time.Second + 2*time.Millisecond),
			Event:     ev(i, decision, reason, destinations[(i-1)%len(destinations)]),
		}, uint64(i), prev)
		prev = r.Hash
		out = append(out, mustJSON(t, r))
		if isCP[uint64(i)] {
			cp, err := SignCheckpoint(priv, "corpus-key", r.Seq, r.Hash, r.Seq,
				t0.Add(time.Duration(i)*time.Second+500*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, mustJSON(t, cp))
		}
	}
	return out
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func logOf(lines [][]byte) string { return string(bytes.Join(lines, []byte("\n"))) + "\n" }

func without(lines [][]byte, i int) [][]byte {
	out := append([][]byte{}, lines[:i]...)
	return append(out, lines[i+1:]...)
}

func isCPLine(l []byte) bool { return bytes.Contains(l, []byte(`"type":"checkpoint"`)) }

func noCheckpoints(lines [][]byte) [][]byte {
	var out [][]byte
	for _, l := range lines {
		if !isCPLine(l) {
			out = append(out, l)
		}
	}
	return out
}

func p(kind string, seq uint64) corpusProblem { return corpusProblem{kind, seq} }

// buildCorpus constructs every vector and writes its expectation from the
// specification. Line indices below refer to chainLines output, where a
// checkpoint line follows the record it covers.
func buildCorpus(t *testing.T) corpus {
	pub, priv := corpusKey()

	c := corpus{
		Spec:      "docs/rfcs/RFC-0009-evidence-chain-format.md",
		Version:   ChainVersion,
		KeySeed:   corpusSeed,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Note: "Expected results are written from RFC-0009, not generated by any verifier. " +
			"The key is SHA-256(key_seed) used as an Ed25519 seed; it is public and must never sign real evidence.",
	}

	// --- hash vectors: one record's canonical input and hash, for debugging
	// an implementation one field at a time.
	hv := func(name string, r Record) {
		r = Link(r, r.Seq, r.PrevHash)
		c.HashVectors = append(c.HashVectors, hashVector{
			Name: name, Record: string(mustJSON(t, r)),
			CanonicalInput: string(canonicalRecordInput(r)), Hash: r.Hash,
		})
	}
	hv("ordinary egress denial", Record{Seq: 1, PrevHash: GenesisHash, EventName: "confine.egress.denied",
		Timestamp: t0.Add(1234567 * time.Nanosecond), Event: ev(1, "deny", "metadata_endpoint", "169.254.169.254:80")})
	hv("multibyte UTF-8: lengths are bytes, not characters", Record{Seq: 7, PrevHash: strings.Repeat("ab", 32),
		EventName: "observed.agent.activity", Timestamp: t0,
		Event: GatewayEvent{AgentID: "agent-ü-東京", Action: "tool.検索", ResourceID: "émoji-🙂",
			Decision: "observed", Producer: ProducerRecorder, Federated: true, SourceTenant: "partner-b", Risk: "write"}})
	hv("zero times and negative integer", Record{Seq: 2, PrevHash: strings.Repeat("0", 64), EventName: "x",
		Timestamp: t0, Event: GatewayEvent{HTTPStatus: -1, LatencyMS: 0}})

	add := func(name, desc string, lines [][]byte, key string, anchor []byte, exp corpusExpect) {
		v := corpusVector{Name: name, Description: desc, Log: logOf(lines), Key: key, Expect: exp}
		if anchor != nil {
			v.Anchor = anchor
		}
		if v.Expect.Problems == nil {
			v.Expect.Problems = []corpusProblem{}
		}
		c.VerifyVectors = append(c.VerifyVectors, v)
	}

	// chainLines(6, 3, 6) lays out as:
	//   0:r1 1:r2 2:r3 3:cp3 4:r4 5:r5 6:r6 7:cp6
	base := chainLines(t, 6, 3, 6)

	// ---------------------------------------------------------------- positive
	add("intact_fully_anchored", "Six records, checkpoints after 3 and 6.", base, "test", nil,
		corpusExpect{Intact: true, Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6})

	add("intact_unanchored_tail", "The last checkpoint covers seq 3; records 4-6 are chained but unsigned.",
		base[:7], "test", nil,
		corpusExpect{Intact: true, Records: 6, Checkpoints: 1, HeadSeq: 6, SignedThrough: 3, UnanchoredRecords: 3})

	add("chain_only_without_key", "No key given: links and hashes are checked, signatures are not, and no unanchored problem arises.",
		noCheckpoints(base), "", nil,
		corpusExpect{Intact: true, Records: 6, Checkpoints: 0, HeadSeq: 6})

	blank := append([][]byte{}, base[:4]...)
	blank = append(blank, []byte("   "), []byte(""))
	add("blank_lines_ignored", "Whitespace-only and empty lines are skipped.", blank, "test", nil,
		corpusExpect{Intact: true, Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3})

	// Same instants, spelled with an offset and with padded fractions. The
	// hash is over TS(t), so these must still verify.
	offs := append([][]byte{}, base[:4]...)
	offs[0] = []byte(strings.Replace(string(offs[0]), `"timestamp":"2026-09-01T12:00:01.002Z"`,
		`"timestamp":"2026-09-01T17:30:01.002000000+05:30"`, 1))
	if bytes.Equal(offs[0], base[0]) {
		t.Fatal("offset vector: substitution did not apply")
	}
	add("timestamp_offset_normalised", "Record 1's timestamp is written with a +05:30 offset and padded nanoseconds; TS() normalises it to the hashed form.",
		offs, "test", nil, corpusExpect{Intact: true, Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3})

	// A v1 record: hashed without fields 21-25.
	v1 := Record{Version: ChainVersionV1, Seq: 1, PrevHash: GenesisHash, EventName: "gateway.decision",
		Timestamp: t0, Event: ev(1, "allow", "allowed", "acme/app")}
	v1.Hash = ComputeHash(v1)
	cpv1, _ := SignCheckpoint(priv, "corpus-key", 1, v1.Hash, 1, t0.Add(time.Second))
	add("superseded_v1_record", "A v1 record verifies under v1 rules and is reported, without clearing intact.",
		[][]byte{mustJSON(t, v1), mustJSON(t, cpv1)}, "test", nil,
		corpusExpect{Intact: true, Records: 1, Checkpoints: 1, HeadSeq: 1, SignedThrough: 1,
			Problems: []corpusProblem{p("superseded_format", 1)}})

	anchor6 := base[7]
	anchor3 := base[3]
	add("anchor_honest_growth", "The anchor is the checkpoint at 3; the log has legitimately grown past it.",
		base, "test", anchor3, corpusExpect{Intact: true, Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6})

	// ---------------------------------------------------------------- negative
	edit := append([][]byte{}, base...)
	edit[1] = bytes.Replace(edit[1], []byte(`"Decision":"deny"`), []byte(`"Decision":"allow"`), 1)
	add("content_edited", "Record 2's decision flipped from deny to allow; nothing else changed.",
		edit, "test", nil, corpusExpect{Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("content", 2)}})

	add("record_deleted", "Record 2 removed. Record 3 now follows 1: wrong seq, wrong link.",
		without(base, 1), "test", nil, corpusExpect{Records: 5, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("sequence", 3), p("chain", 3)}})

	swap := append([][]byte{}, base...)
	swap[4], swap[5] = swap[5], swap[4]
	add("records_reordered", "Records 4 and 5 swapped. Each is out of sequence and mislinked, and so is record 6, which links to 5 but now follows 4. The checkpoint at 6 still matches: it commits to record 6's own hash, and record 6 was not altered.",
		swap, "test", nil, corpusExpect{Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("sequence", 5), p("chain", 5), p("sequence", 4), p("chain", 4), p("sequence", 6), p("chain", 6)}})

	add("checkpoints_stripped", "Every checkpoint removed, verified with a key: nothing is pinned.",
		noCheckpoints(base), "test", nil, corpusExpect{Records: 6, HeadSeq: 6, UnanchoredRecords: 6,
			Problems: []corpusProblem{p("unanchored", 6)}})

	// Record 2 rewritten and the chain recomputed from it, original
	// checkpoints kept: the forgery an attacker without the key produces.
	var recs []Record
	for _, l := range noCheckpoints(base) {
		var r Record
		_ = json.Unmarshal(l, &r)
		recs = append(recs, r)
	}
	recs[1].Event.Decision, recs[1].Event.ReasonCode = "allow", "allowed"
	prev := GenesisHash
	var rechained [][]byte
	for i := range recs {
		recs[i] = Link(recs[i], recs[i].Seq, prev)
		prev = recs[i].Hash
		rechained = append(rechained, mustJSON(t, recs[i]))
		if recs[i].Seq == 3 {
			rechained = append(rechained, base[3])
		}
		if recs[i].Seq == 6 {
			rechained = append(rechained, base[7])
		}
	}
	add("rewritten_and_rechained", "Record 2 altered and every later hash recomputed; the original checkpoints no longer match the new heads.",
		rechained, "test", nil, corpusExpect{Records: 6, Checkpoints: 2, HeadSeq: 6, UnanchoredRecords: 6,
			Problems: []corpusProblem{p("checkpoint", 3), p("checkpoint", 6)}})

	otherSeed := sha256.Sum256([]byte("a different key"))
	otherPriv := ed25519.NewKeyFromSeed(otherSeed[:])
	var hdr Record
	_ = json.Unmarshal(base[6], &hdr)
	foreign, _ := SignCheckpoint(otherPriv, "attacker", 6, hdr.Hash, 6, t0.Add(time.Hour))
	forged := append(append([][]byte{}, base[:7]...), mustJSON(t, foreign))
	add("checkpoint_foreign_key", "The final checkpoint is signed by a key other than the one given.",
		forged, "test", nil, corpusExpect{Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 3, UnanchoredRecords: 3,
			Problems: []corpusProblem{p("checkpoint", 6)}})

	add("rollback_detected_by_anchor", "Truncated exactly after the checkpoint at 3. Alone it verifies; the anchor at 6 shows three records gone.",
		base[:4], "test", anchor6, corpusExpect{Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3,
			Problems: []corpusProblem{p("rollback", 3)}})

	add("rollback_invisible_without_anchor", "The same truncation, no anchor: RFC-0009 §5 -- nothing in the file can reveal it.",
		base[:4], "test", nil, corpusExpect{Intact: true, Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3})

	add("anchor_missing", "The anchor names seq 6, the log reaches 6, but its only checkpoint is at 3.",
		base[:7], "test", anchor6, corpusExpect{Records: 6, Checkpoints: 1, HeadSeq: 6, SignedThrough: 3, UnanchoredRecords: 3,
			Problems: []corpusProblem{p("missing_anchor", 6)}})

	// Equivocation: the producer signed a checkpoint at 3 over a DIFFERENT
	// head -- the rewritten history -- and gave that one to the auditor.
	forkCP, _ := SignCheckpoint(priv, "corpus-key", 3, recs[2].Hash, 3, t0.Add(10*time.Second))
	add("anchor_forked", "The auditor's anchor at 3 is validly signed but commits to a different head than this log's checkpoint at 3: two histories.",
		base, "test", mustJSON(t, forkCP), corpusExpect{Records: 6, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("forked", 3)}})

	unsignedAnchor := bytes.Replace(anchor6, []byte(`"signature":"`), []byte(`"signature":"AAAA`), 1)
	add("anchor_invalid", "The anchor's signature does not verify under the given key, so it is not compared at all.",
		base[:4], "test", unsignedAnchor, corpusExpect{Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3,
			Problems: []corpusProblem{p("anchor_invalid", 6)}})

	dup := append([][]byte{}, base...)
	dup[1] = bytes.Replace(dup[1], []byte(`"event":{`), []byte(`"event":{"Decision":"allow",`), 1)
	add("duplicate_member", "Record 2 names Decision twice. Last-wins parsing would hash it unchanged; RFC-0009 §1 requires rejection.",
		dup, "test", nil, corpusExpect{Records: 5, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("malformed", 2), p("sequence", 3), p("chain", 3)}})

	cased := append([][]byte{}, base...)
	cased[1] = bytes.Replace(cased[1], []byte(`"Decision":"deny"`), []byte(`"Decision":"allow","decision":"deny"`), 1)
	add("case_variant_member", "Record 2 carries Decision and decision. A case-insensitive parser reads the genuine value and the hash matches, while a case-sensitive reader shows allow. RFC-0009 §1 makes the line malformed.",
		cased, "test", nil, corpusExpect{Records: 5, Checkpoints: 2, HeadSeq: 6, SignedThrough: 6,
			Problems: []corpusProblem{p("malformed", 2), p("sequence", 3), p("chain", 3)}})

	noTS := append([][]byte{}, base[:4]...)
	noTS[2] = bytes.Replace(noTS[2], []byte(`"timestamp":`), []byte(`"timestanp":`), 1)
	add("record_member_missing", "Record 3's timestamp key is misspelled. A missing record member is malformed, not a zero value (§2.1).",
		noTS, "test", nil, corpusExpect{Records: 2, Checkpoints: 1, HeadSeq: 2, UnanchoredRecords: 2,
			Problems: []corpusProblem{p("malformed", 3), p("checkpoint", 3)}})

	noSeq := append([][]byte{}, base[:4]...)
	noSeq[3] = bytes.Replace(noSeq[3], []byte(`"issuedAt":`), []byte(`"isuedAt":`), 1)
	add("checkpoint_member_missing", "The checkpoint's issuedAt key is misspelled: malformed (§4.1), rather than a signature failure over a zero time.",
		noSeq, "test", nil, corpusExpect{Records: 3, HeadSeq: 3, UnanchoredRecords: 3,
			Problems: []corpusProblem{p("malformed", 4), p("unanchored", 3)}})

	// A log that ends on a record numbered below the last verified
	// checkpoint: r1 r2 r3 cp3, then r1 again. Unsigned arithmetic wrapped
	// here in two verifiers; unanchoredRecords is floored at zero.
	behind := append(append([][]byte{}, base[:4]...), base[0])
	add("head_behind_signed", "The log repeats record 1 after the checkpoint at 3, so it ends at seq 1 with seq 3 signed. unanchoredRecords is max(0, 1-3) = 0, not a wrapped unsigned value.",
		behind, "test", nil, corpusExpect{Records: 4, Checkpoints: 1, HeadSeq: 1, SignedThrough: 3,
			Problems: []corpusProblem{p("sequence", 1), p("chain", 1)}})

	// RFC-0009 §2.3 and §2.4: the edges where common parsers disagree. Each
	// alters record 3 of a three-record log whose checkpoint covers seq 3;
	// a malformed record 3 leaves the chain at 2, so the checkpoint no longer
	// matches either.
	edge := func(name, desc, from, to string, malformed bool) {
		lines := append([][]byte{}, base[:4]...)
		lines[2] = bytes.Replace(lines[2], []byte(from), []byte(to), 1)
		if bytes.Equal(lines[2], base[2]) {
			t.Fatalf("%s: substitution did not apply", name)
		}
		exp := corpusExpect{Intact: true, Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3}
		if malformed {
			exp = corpusExpect{Records: 2, Checkpoints: 1, HeadSeq: 2, UnanchoredRecords: 2,
				Problems: []corpusProblem{p("malformed", 3), p("checkpoint", 3)}}
		}
		add(name, desc, lines, "test", nil, exp)
	}
	edge("timestamp_lowercase_z", "A lowercase z. RFC 3339 allows it; RFC-0009 §2.3 does not, because parsers disagree.",
		`"timestamp":"2026-09-01T12:00:03.002Z"`, `"timestamp":"2026-09-01T12:00:03.002z"`, true)
	edge("timestamp_comma_fraction", "A comma before the fraction, which some parsers accept.",
		`"timestamp":"2026-09-01T12:00:03.002Z"`, `"timestamp":"2026-09-01T12:00:03,002Z"`, true)
	edge("timestamp_offset_24", "An offset of +24:00, which some parsers accept.",
		`"timestamp":"2026-09-01T12:00:03.002Z"`, `"timestamp":"2026-09-02T12:00:03.002+24:00"`, true)
	edge("timestamp_ten_digits", "Ten fractional digits; some parsers truncate them silently.",
		`"timestamp":"2026-09-01T12:00:03.002Z"`, `"timestamp":"2026-09-01T12:00:03.0020000000Z"`, true)
	edge("timestamp_not_a_date", "February 30th.",
		`"StartedAt":"2026-09-01T12:00:03Z"`, `"StartedAt":"2026-02-30T12:00:03Z"`, true)
	edge("integer_quoted", "HTTPStatus as the string \"403\". A quoted number is a string (§2.4).",
		`"HTTPStatus":403`, `"HTTPStatus":"403"`, true)
	edge("integer_with_fraction", "LatencyMS as 1.0: a number, but not an integer.",
		`"LatencyMS":1`, `"LatencyMS":1.0`, true)
	edge("record_member_null", "A null record member is malformed, not an empty string.",
		`"eventName":"confine.egress.denied"`, `"eventName":null`, true)
	edge("event_member_null_is_absent", "A null event member is absent, and hashes as its zero value (§2.2), so this record still verifies.",
		`"TraceID":""`, `"TraceID":null`, false)
	edge("event_member_unknown_is_ignored", "A member the table does not define is ignored and not hashed.",
		`"TraceID":""`, `"TraceID":"","x-vendor-note":"anything"`, false)

	junk := append(append([][]byte{}, base[:2]...), []byte(`{"v":"agw-evidence-v2","seq":`))
	junk = append(junk, base[2:4]...)
	add("malformed_line", "A truncated JSON line between records 2 and 3.",
		junk, "test", nil, corpusExpect{Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3,
			Problems: []corpusProblem{p("malformed", 3)}})

	vers := append([][]byte{}, base[:4]...)
	vers[2] = bytes.Replace(vers[2], []byte(`"v":"agw-evidence-v2"`), []byte(`"v":"agw-evidence-v9"`), 1)
	add("unknown_version", "Record 3 declares a version the verifier does not implement; it is refused, not guessed at.",
		vers, "test", nil, corpusExpect{Records: 2, Checkpoints: 1, HeadSeq: 2, UnanchoredRecords: 2,
			Problems: []corpusProblem{p("version", 3), p("checkpoint", 3)}})

	upper := append([][]byte{}, base[:4]...)
	var r1 Record
	_ = json.Unmarshal(upper[0], &r1)
	upper[0] = bytes.Replace(upper[0], []byte(`"hash":"`+r1.Hash), []byte(`"hash":"`+strings.ToUpper(r1.Hash)), 1)
	add("hash_uppercase", "Record 1's hash written in uppercase hex. Hashes are lowercase; this is a different string.",
		upper, "test", nil, corpusExpect{Records: 3, Checkpoints: 1, HeadSeq: 3, SignedThrough: 3,
			Problems: []corpusProblem{p("content", 1), p("chain", 2)}})

	return c
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v (run: go test ./pkg/evidence -run TestEvidenceCorpus -update-corpus)", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestEvidenceCorpusIsCurrent: the checked-in corpus is exactly what the
// builder produces. Ed25519 is deterministic, so any drift is a real change.
func TestEvidenceCorpusIsCurrent(t *testing.T) {
	built := buildCorpus(t)
	out, err := json.MarshalIndent(built, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateCorpus {
		if err := os.MkdirAll(filepath.Dir(corpusPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(corpusPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", corpusPath)
		return
	}
	onDisk, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if !bytes.Equal(onDisk, out) {
		t.Fatal("conformance corpus is stale or was edited by hand; regenerate with -update-corpus and review the diff")
	}
}

// TestEvidenceCorpusKeyIsTheDocumentedTestKey guards against a corpus
// regenerated with a real key.
func TestEvidenceCorpusKeyIsTheDocumentedTestKey(t *testing.T) {
	c := loadCorpus(t)
	pub, _ := corpusKey()
	if c.KeySeed != corpusSeed || c.PublicKey != base64.StdEncoding.EncodeToString(pub) {
		t.Fatal("corpus was generated with a key other than the documented public test seed")
	}
}

// TestVerifyConformsToCorpus holds the reference verifier to the
// specification's expected results.
func TestVerifyConformsToCorpus(t *testing.T) {
	c := loadCorpus(t)
	pubRaw, _ := base64.StdEncoding.DecodeString(c.PublicKey)

	for _, hvec := range c.HashVectors {
		var r Record
		if err := json.Unmarshal([]byte(hvec.Record), &r); err != nil {
			t.Fatalf("%s: %v", hvec.Name, err)
		}
		if got := string(canonicalRecordInput(r)); got != hvec.CanonicalInput {
			t.Errorf("hash vector %q: canonical input differs\n got %q\nwant %q", hvec.Name, got, hvec.CanonicalInput)
		}
		if got := ComputeHash(r); got != hvec.Hash {
			t.Errorf("hash vector %q: hash %s, want %s", hvec.Name, got, hvec.Hash)
		}
		sum := sha256.Sum256([]byte(hvec.CanonicalInput))
		if hex.EncodeToString(sum[:]) != hvec.Hash {
			t.Errorf("hash vector %q is internally inconsistent", hvec.Name)
		}
	}

	for _, v := range c.VerifyVectors {
		t.Run(v.Name, func(t *testing.T) {
			var pub ed25519.PublicKey
			if v.Key == "test" {
				pub = pubRaw
			}
			var anchor *Checkpoint
			if len(v.Anchor) > 0 {
				anchor = &Checkpoint{}
				if err := json.Unmarshal(v.Anchor, anchor); err != nil {
					t.Fatal(err)
				}
			}
			res, problems, err := VerifyWithAnchor(strings.NewReader(v.Log), pub, anchor)
			if err != nil {
				t.Fatal(err)
			}
			got := corpusExpect{
				Intact: res.Intact, Records: res.Records, Checkpoints: res.Checkpoints,
				HeadSeq: res.HeadSeq, SignedThrough: res.SignedThrough,
				UnanchoredRecords: res.UnanchoredRecords, Problems: []corpusProblem{},
			}
			for _, pr := range problems {
				got.Problems = append(got.Problems, corpusProblem{pr.Kind, pr.Seq})
			}
			if !reflect.DeepEqual(got, v.Expect) {
				t.Errorf("%s\n got  %+v\n want %+v", v.Description, got, v.Expect)
			}
		})
	}
}
