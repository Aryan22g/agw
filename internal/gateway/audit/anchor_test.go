package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/Aryan22g/agw/pkg/ags1/signer"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// buildChain produces a signed chain of n records for the tamper tests.
func buildChain(t *testing.T, n int, checkpointEvery int) ([][]byte, ed25519.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return buildChainWithKey(t, n, checkpointEvery, priv, "a")
}

// buildChainWithKey lets two chains share a signer, which is what an
// equivocating producer -- one key, two histories -- looks like.
func buildChainWithKey(t *testing.T, n int, checkpointEvery int, priv ed25519.PrivateKey, agent string) ([][]byte, ed25519.PublicKey) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)

	var lines [][]byte
	prev := GenesisHash
	var rec Record
	for i := 1; i <= n; i++ {
		rec = Link(Record{
			Version:   ChainVersion,
			EventName: "confine.egress.denied",
			Timestamp: time.Now().UTC(),
			Event:     GatewayEvent{AgentID: agent, Decision: "deny", ReasonCode: "not_in_allowlist"},
		}, uint64(i), prev)
		prev = rec.Hash

		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)

		if i%checkpointEvery == 0 {
			cp, err := SignCheckpoint(priv, "k1", rec.Seq, rec.Hash, rec.Seq, time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			cpLine, err := json.Marshal(cp)
			if err != nil {
				t.Fatal(err)
			}
			lines = append(lines, cpLine)
		}
	}
	return lines, pub
}

func joined(lines [][]byte) *bytes.Reader {
	return bytes.NewReader(bytes.Join(lines, []byte("\n")))
}

// TestChainWithoutCheckpointsIsRefused pins a defect the gym found by deleting
// every checkpoint from a real evidence file and asking the verifier what it
// thought.
//
// It said VERIFIED. A chain with no checkpoint is internally consistent and
// proves nothing: anyone able to write the file can rewrite it from genesis
// and recompute every hash. Answering "verified" to a caller who supplied a
// public key -- that is, who asked whether the signatures hold -- when there
// are no signatures at all is the wrong answer to the question asked.
func TestChainWithoutCheckpointsIsRefused(t *testing.T) {
	lines, pub := buildChain(t, 12, 5)

	var stripped [][]byte
	for _, l := range lines {
		if !bytes.Contains(l, []byte(`"type":"checkpoint"`)) {
			stripped = append(stripped, l)
		}
	}

	res, problems, err := Verify(joined(stripped), pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) == 0 {
		t.Fatal("a chain with no checkpoints verified clean against a public key")
	}
	if res.Intact {
		t.Error("Intact is true for a chain nothing has signed")
	}
	if problems[0].Kind != "unanchored" {
		t.Errorf("problem kind = %q, want %q", problems[0].Kind, "unanchored")
	}

	// Chain-only verification is a different question and must still answer
	// it: without a key the caller asked whether records were edited, and
	// none were.
	if _, problems, err := Verify(joined(stripped), nil); err != nil || len(problems) > 0 {
		t.Errorf("chain-only verification should still pass: %v %v", err, problems)
	}
}

// TestUnanchoredTailIsReported covers the ordinary case: a live log always has
// records after its last checkpoint. That is not tampering, but those records
// are precisely the ones that can be removed without a trace, so the verifier
// has to say how many there are rather than reporting a bare success.
func TestUnanchoredTailIsReported(t *testing.T) {
	lines, pub := buildChain(t, 12, 5) // checkpoints at 5 and 10; 11 and 12 are bare

	res, problems, err := Verify(joined(lines), pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("an intact chain reported problems: %v", problems)
	}
	if res.SignedThrough != 10 {
		t.Errorf("SignedThrough = %d, want 10", res.SignedThrough)
	}
	if res.UnanchoredRecords != 2 {
		t.Errorf("UnanchoredRecords = %d, want 2", res.UnanchoredRecords)
	}
}

// TestAnchorDetectsRollback covers the alteration nothing inside the file can
// catch: truncating a log exactly at a checkpoint boundary leaves a shorter log
// in which every record chains and every checkpoint verifies.
//
// The way out is one piece of state from outside the file. An auditor who kept
// any earlier checkpoint can prove the log was rolled back.
func TestAnchorDetectsRollback(t *testing.T) {
	lines, pub := buildChain(t, 20, 5)

	// The checkpoint the auditor kept: the last one in the full log.
	var anchor Checkpoint
	for _, l := range lines {
		if bytes.Contains(l, []byte(`"type":"checkpoint"`)) {
			if err := json.Unmarshal(l, &anchor); err != nil {
				t.Fatal(err)
			}
		}
	}
	if anchor.Seq != 20 {
		t.Fatalf("anchor seq = %d, want 20", anchor.Seq)
	}

	// Truncate back to the checkpoint at seq 10.
	var rolled [][]byte
	for _, l := range lines {
		rolled = append(rolled, l)
		if bytes.Contains(l, []byte(`"type":"checkpoint"`)) {
			var cp Checkpoint
			_ = json.Unmarshal(l, &cp)
			if cp.Seq == 10 {
				break
			}
		}
	}

	// Without the anchor the rollback is invisible, which is the point.
	if _, problems, err := Verify(joined(rolled), pub); err != nil || len(problems) > 0 {
		t.Fatalf("expected a truncated-at-checkpoint log to look clean on its own: %v %v",
			err, problems)
	}

	res, problems, err := VerifyWithAnchor(joined(rolled), pub, &anchor)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) == 0 {
		t.Fatal("the anchor did not detect the rollback")
	}
	if problems[0].Kind != "rollback" {
		t.Fatalf("problem kind = %q, want %q (%s)", problems[0].Kind, "rollback", problems[0].Detail)
	}
	if !strings.Contains(problems[0].Detail, "10 record(s) have been removed") {
		t.Errorf("the problem should say how much was removed: %s", problems[0].Detail)
	}
	if res.Intact {
		t.Error("Intact is true for a rolled-back log")
	}
}

// TestAnchorDetectsAForkedHistory covers the other shape: a log long enough to
// contain the anchor, whose checkpoint at that sequence commits to a different
// head. Two different histories under one key, not one shortened one.
func TestAnchorDetectsAForkedHistory(t *testing.T) {
	// One key, two histories: the producer signed both, and gave the
	// auditor a checkpoint from the one it later discarded.
	_, priv, _ := ed25519.GenerateKey(nil)
	linesA, pubA := buildChainWithKey(t, 15, 5, priv, "a")
	linesB, _ := buildChainWithKey(t, 15, 5, priv, "b")

	var anchorB Checkpoint
	for _, l := range linesB {
		if bytes.Contains(l, []byte(`"type":"checkpoint"`)) {
			var cp Checkpoint
			_ = json.Unmarshal(l, &cp)
			if cp.Seq == 10 {
				anchorB = cp
				break
			}
		}
	}

	_, problems, err := VerifyWithAnchor(joined(linesA), pubA, &anchorB)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) == 0 {
		t.Fatal("an anchor from a different history was not detected")
	}
	if problems[0].Kind != "forked" {
		t.Fatalf("problem kind = %q, want %q (%s)", problems[0].Kind, "forked", problems[0].Detail)
	}
}

// TestAnchorAcceptsAnHonestLog makes sure the anchor check does not fire on a
// log that simply grew since the auditor last read it.
func TestAnchorAcceptsAnHonestLog(t *testing.T) {
	lines, pub := buildChain(t, 20, 5)

	var anchor Checkpoint
	for _, l := range lines {
		if bytes.Contains(l, []byte(`"type":"checkpoint"`)) {
			var cp Checkpoint
			_ = json.Unmarshal(l, &cp)
			if cp.Seq == 10 {
				anchor = cp
				break
			}
		}
	}

	_, problems, err := VerifyWithAnchor(joined(lines), pub, &anchor)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) != 0 {
		t.Fatalf("a log that legitimately grew past the anchor reported problems: %v", problems)
	}
}

// TestDuplicateMembersAreMalformed pins RFC-0009 §1. A record naming Decision
// twice must not verify: the verifier and a human's JSON tool could otherwise
// be reading different values out of the same line.
func TestDuplicateMembersAreMalformed(t *testing.T) {
	lines, pub := buildChain(t, 3, 10)
	// Insert a second, earlier "Decision" member into record 2's event. The
	// original (last) value is unchanged, so a last-wins decoder hashes the
	// record exactly as before -- which is the whole danger.
	lines[1] = bytes.Replace(lines[1], []byte(`"event":{`), []byte(`"event":{"Decision":"allow",`), 1)

	res, problems, err := Verify(joined(lines), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact || len(problems) == 0 || problems[0].Kind != "malformed" {
		t.Fatalf("duplicate member accepted: intact=%v problems=%v", res.Intact, problems)
	}
	if !strings.Contains(problems[0].Detail, "duplicate member") {
		t.Errorf("problem should name the cause: %s", problems[0].Detail)
	}
}

// TestAnchorFromAnotherKeyIsNotCompared: an anchor the given key did not sign
// proves nothing, and must not be allowed to manufacture a fork finding.
func TestAnchorFromAnotherKeyIsNotCompared(t *testing.T) {
	linesA, pubA := buildChain(t, 10, 5)
	linesB, _ := buildChain(t, 10, 5) // independent key

	var foreign Checkpoint
	_ = json.Unmarshal(linesB[len(linesB)-1], &foreign)

	_, problems, err := VerifyWithAnchor(joined(linesA), pubA, &foreign)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || problems[0].Kind != "anchor_invalid" {
		t.Fatalf("want exactly anchor_invalid, got %v", problems)
	}
}

// TestCaseVariantMemberCannotMaskADecision pins the attack in
// checkExactNames: a record rewritten so that a case-sensitive reader sees
// one decision while encoding/json hashes another must not verify.
func TestCaseVariantMemberCannotMaskADecision(t *testing.T) {
	lines, pub := buildChain(t, 3, 10)
	// Record 2 is genuinely "deny". Prepend a lowercase twin: Go's decoder
	// reads "decision" into Decision case-insensitively, so without the
	// check the hash would still match.
	lines[1] = bytes.Replace(lines[1], []byte(`"Decision":"deny"`),
		[]byte(`"decision":"allow","Decision":"deny"`), 1)

	res, problems, err := Verify(joined(lines), pub)
	if err != nil {
		t.Fatal(err)
	}
	if res.Intact || len(problems) == 0 || problems[0].Kind != "malformed" {
		t.Fatalf("case-variant member accepted: intact=%v %v", res.Intact, problems)
	}
}

// TestEventMemberNamesMatchTheStruct keeps eventMemberNames complete.
func TestEventMemberNamesMatchTheStruct(t *testing.T) {
	rt := reflect.TypeOf(GatewayEvent{})
	var fields []string
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).IsExported() {
			fields = append(fields, rt.Field(i).Name)
		}
	}
	got := append([]string(nil), eventMemberNames...)
	sort.Strings(fields)
	sort.Strings(got)
	if !reflect.DeepEqual(fields, got) {
		t.Fatalf("eventMemberNames is out of date:\n struct %v\n list   %v", fields, got)
	}
}

// TestQuietLogIsAnchoredWithoutFurtherWrites pins the ticker: the interval
// is a promise about wall-clock time, not about the next write.
func TestQuietLogIsAnchoredWithoutFurtherWrites(t *testing.T) {
	const interval = 200 * time.Millisecond
	_, priv, _ := ed25519.GenerateKey(nil)
	path := t.TempDir() + "/quiet.jsonl"
	sink, err := NewEvidenceSink(EvidenceSinkConfig{
		Path: path, Signer: testSigner{priv}, KeyID: "k",
		CheckpointEvery: 1000, CheckpointInterval: interval,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := sink.Write(context.Background(), "e", GatewayEvent{AgentID: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	// Three writes are far below CheckpointEvery, so nothing may be signed
	// yet -- unless the interval itself has already passed, which on a
	// loaded runner under -race it can. Only a check made inside the
	// interval says anything about writes.
	if got := sink.SignedThrough(); got != 0 && time.Since(start) < interval {
		t.Fatalf("checkpointed early: %d", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for sink.SignedThrough() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := sink.SignedThrough(); got != 3 {
		t.Fatalf("a quiet log was not anchored by the interval: signed through %d of 3", got)
	}
}

type testSigner struct{ priv ed25519.PrivateKey }

func (s testSigner) Sign(m []byte) ([]byte, error) { return ed25519.Sign(s.priv, m), nil }
func (s testSigner) KeyID() string                 { return "k" }

// TestChainSignedThroughASigningDaemon drives the real checkpoint producer
// through a real ags-signd daemon and verifies the result. The daemon's own
// tests built checkpoint messages by hand in the v1 form, so when the chain
// moved to v2 the daemon refused every real checkpoint while its tests kept
// passing. This test uses the producer, so the two cannot drift again.
func TestChainSignedThroughASigningDaemon(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	held, err := signer.FromKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortTempDir(t), "d.sock")
	d, err := signer.NewDaemon(signer.DaemonConfig{
		SocketPath: sock, Signer: held, Purposes: []string{signer.PurposeEvidenceCheckpoint},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = d.Serve() }()
	defer d.Close()

	remote, err := signer.Connect(signer.SeparatedConfig{SocketPath: sock})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ev.jsonl")
	sink, err := NewEvidenceSink(EvidenceSinkConfig{Path: path, Signer: remote, KeyID: remote.KeyID(), CheckpointEvery: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := sink.Write(context.Background(), "e", GatewayEvent{AgentID: "a"}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := sink.CheckpointError(); err != nil {
		t.Fatalf("the daemon refused a real checkpoint: %v", err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	f, _ := os.Open(path)
	defer f.Close()
	res, problems, err := Verify(f, priv.Public().(ed25519.PublicKey))
	if err != nil || len(problems) > 0 || !res.Intact || res.SignedThrough != 5 {
		t.Fatalf("chain signed through the daemon does not verify: %+v %v %v", res, problems, err)
	}
}

// TestFailedCheckpointDoesNotFailTheRecord: the record is written and
// durable; only its anchoring is delayed. Failing the write made a
// fail-closed caller refuse an action the chain recorded as allowed.
func TestFailedCheckpointDoesNotFailTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ev.jsonl")
	sink, err := NewEvidenceSink(EvidenceSinkConfig{Path: path, Signer: refusingSigner{}, KeyID: "k", CheckpointEvery: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	rec, err := sink.Write(context.Background(), "e", GatewayEvent{AgentID: "a", Decision: "allow"})
	if err != nil {
		t.Fatalf("a checkpoint failure failed the record write: %v", err)
	}
	if rec.Seq != 1 || sink.CheckpointError() == nil {
		t.Fatalf("seq %d, checkpoint error %v", rec.Seq, sink.CheckpointError())
	}
}

type refusingSigner struct{}

func (refusingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("signer unavailable") }
func (refusingSigner) KeyID() string               { return "k" }

// shortTempDir keeps unix socket paths under macOS's 104-byte limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "agw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
