package evidence_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/signer"
	"github.com/Aryan22g/agw/pkg/evidence"
)

// writeLog produces a signed evidence log with n decisions.
func writeLog(t *testing.T, n int) (path string, pub ed25519.PublicKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	held, err := signer.FromKey(priv, "gw-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	path = filepath.Join(t.TempDir(), "decisions.jsonl")
	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
		Path: path, Signer: held, KeyID: "gw-test", CheckpointEvery: 5,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	for i := 0; i < n; i++ {
		ev := evidence.GatewayEvent{
			EventID:    fmt.Sprintf("evt_%d", i),
			TenantID:   "tenant-alpha",
			AgentID:    "agent-support",
			DecisionID: fmt.Sprintf("dec_%d", i),
			Action:     "github.issue.create",
			ResourceID: "acme/app",
			Decision:   "allow",
			ReasonCode: "allowed",
			HTTPStatus: 200,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
		}
		if _, err := sink.Write(context.Background(), "gateway.request.allowed", ev); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path, pub
}

func verifyFile(t *testing.T, path string, pub ed25519.PublicKey) (*evidence.VerifyResult, []evidence.VerifyProblem) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	res, problems, err := evidence.Verify(f, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res, problems
}

func TestIntactLogVerifies(t *testing.T) {
	path, pub := writeLog(t, 12)

	res, problems := verifyFile(t, path, pub)
	if !res.Intact {
		t.Fatalf("a clean log failed verification: %v", problems)
	}
	if res.Records != 12 {
		t.Errorf("records = %d, want 12", res.Records)
	}
	if res.Checkpoints == 0 {
		t.Error("no checkpoints were written")
	}
	if res.SignedThrough != 12 {
		t.Errorf("signed through %d, want 12: the closing checkpoint should anchor every record",
			res.SignedThrough)
	}
}

// TestEditedRecordDetected is the property the product is sold on: changing a
// decision after the fact must be detectable.
func TestEditedRecordDetected(t *testing.T) {
	path, pub := writeLog(t, 10)

	// Flip a denial into an allow, the edit someone covering their tracks
	// would actually make.
	lines := readLines(t, path)
	target := 4
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[target]), &rec); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	event := rec["event"].(map[string]any)
	event["Decision"] = "deny"
	event["ReasonCode"] = "policy_denied"
	edited, _ := json.Marshal(rec)
	lines[target] = string(edited)
	writeLines(t, path, lines)

	res, problems := verifyFile(t, path, pub)
	if res.Intact {
		t.Fatal("an edited decision record passed verification")
	}
	if len(problems) == 0 {
		t.Fatal("no problem reported for an edited record")
	}

	// The break must point at the edited record, not merely say "invalid".
	found := false
	for _, p := range problems {
		if p.Kind == "content" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a content-tampering problem, got %v", problems)
	}
}

// TestDeletedRecordDetected: removing an inconvenient decision must not be
// silent. This is the most likely real-world tampering.
func TestDeletedRecordDetected(t *testing.T) {
	path, pub := writeLog(t, 10)

	lines := readLines(t, path)
	var kept []string
	removed := 0
	for _, l := range lines {
		if removed == 0 && strings.Contains(l, `"seq":6`) {
			removed++
			continue
		}
		kept = append(kept, l)
	}
	if removed == 0 {
		t.Fatal("test setup: no record removed")
	}
	writeLines(t, path, kept)

	res, problems := verifyFile(t, path, pub)
	if res.Intact {
		t.Fatal("a log with a deleted record passed verification")
	}

	found := false
	for _, p := range problems {
		if p.Kind == "sequence" || p.Kind == "chain" {
			found = true
		}
	}
	if !found {
		t.Errorf("deletion was not reported as a sequence or chain break: %v", problems)
	}
}

// TestTruncationDetected: silently dropping the tail of the log must be
// caught by the checkpoint, which commits to a sequence that no longer exists.
func TestTruncationDetected(t *testing.T) {
	path, pub := writeLog(t, 12)

	lines := readLines(t, path)
	// Keep everything through the first checkpoint, then drop the rest and
	// re-append that checkpoint so the file still ends with a signature.
	var head []string
	var cp string
	for _, l := range lines {
		if strings.Contains(l, `"type":"checkpoint"`) {
			cp = l
			break
		}
		head = append(head, l)
	}
	if cp == "" {
		t.Fatal("test setup: no checkpoint found")
	}
	// Drop two records that the checkpoint covers.
	writeLines(t, path, append(head[:len(head)-2], cp))

	res, problems := verifyFile(t, path, pub)
	if res.Intact {
		t.Fatal("a truncated log passed verification")
	}
	if len(problems) == 0 {
		t.Fatal("truncation produced no problem")
	}
}

// TestForgedLogWithoutKeyDetected is the reason checkpoints exist. An attacker
// who rewrites the whole file can make the chain perfectly self-consistent --
// only a signature they cannot produce exposes it.
func TestForgedLogWithoutKeyDetected(t *testing.T) {
	_, realPub := writeLog(t, 5)

	// Attacker rebuilds a clean, internally consistent chain with their own
	// key and their own preferred history.
	forgedPath, _ := writeLog(t, 5)

	res, problems := verifyFile(t, forgedPath, realPub)
	if res.Intact {
		t.Fatal("a forged log signed with an attacker's key verified against the real public key")
	}

	found := false
	for _, p := range problems {
		if p.Kind == "checkpoint" {
			found = true
		}
	}
	if !found {
		t.Errorf("forgery was not caught at the checkpoint: %v", problems)
	}
}

// TestChainSurvivesRestart: a restart must continue the chain, not start a new
// one, or every restart would look like tampering.
func TestChainSurvivesRestart(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := filepath.Join(t.TempDir(), "decisions.jsonl")

	write := func(n int) {
		held, err := signer.FromKey(priv, "gw")
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
			Path: path, Signer: held, KeyID: "gw", CheckpointEvery: 100,
		})
		if err != nil {
			t.Fatalf("sink: %v", err)
		}
		for i := 0; i < n; i++ {
			if _, err := sink.Write(context.Background(), "gateway.request.allowed",
				evidence.GatewayEvent{EventID: fmt.Sprintf("e%d", i), Decision: "allow"}); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}

	write(3)
	write(3) // simulated restart

	res, problems := verifyFile(t, path, pub)
	if !res.Intact {
		t.Fatalf("chain broke across a restart: %v", problems)
	}
	if res.Records != 6 {
		t.Errorf("records = %d, want 6 across two runs", res.Records)
	}
}

// TestVerifierNeedsOnlyLogAndKey: an auditor must be able to verify without
// the gateway, the database, or anything the vendor controls.
func TestVerifierNeedsOnlyLogAndKey(t *testing.T) {
	path, pub := writeLog(t, 6)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	res, problems, err := evidence.Verify(strings.NewReader(string(data)), pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Intact {
		t.Fatalf("verification from bytes alone failed: %v", problems)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// rebuildChain simulates a knowledgeable attacker: edit a record, then
// recompute every subsequent hash so the chain is internally perfect again.
//
// Checkpoints keep their original positions in the file, because that is what
// a real attacker would do -- they cannot forge a signature, so their best
// move is to leave the signed lines exactly where they were and hope the
// rewritten records slip past.
func rebuildChain(t *testing.T, path string, dropTrailingCheckpoint bool) {
	t.Helper()

	type entry struct {
		isCheckpoint bool
		raw          string
		rec          evidence.Record
	}

	var entries []entry
	for _, l := range readLines(t, path) {
		if strings.Contains(l, `"type":"checkpoint"`) {
			entries = append(entries, entry{isCheckpoint: true, raw: l})
			continue
		}
		var r evidence.Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		entries = append(entries, entry{rec: r})
	}

	edited := false
	for i := range entries {
		if entries[i].isCheckpoint {
			continue
		}
		if entries[i].rec.Event.Decision == "allow" && !edited {
			entries[i].rec.Event.Decision = "deny"
			entries[i].rec.Event.ReasonCode = "policy_denied"
			edited = true
		}
	}
	if !edited {
		t.Fatal("test setup: nothing edited")
	}

	// Recompute the whole chain, leaving checkpoint lines untouched and in
	// place.
	prev := evidence.GenesisHash
	lastCheckpoint := -1
	var out []string
	for i := range entries {
		if entries[i].isCheckpoint {
			lastCheckpoint = len(out)
			out = append(out, entries[i].raw)
			continue
		}
		entries[i].rec = evidence.Link(entries[i].rec, entries[i].rec.Seq, prev)
		prev = entries[i].rec.Hash
		b, err := json.Marshal(entries[i].rec)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out = append(out, string(b))
	}

	if dropTrailingCheckpoint && lastCheckpoint >= 0 {
		out = append(out[:lastCheckpoint], out[lastCheckpoint+1:]...)
	}

	writeLines(t, path, out)
}

// TestChainRebuildCaughtByCheckpoint covers the attack the hash chain alone
// does NOT stop: an attacker who understands the format edits a record and
// recomputes every hash after it, producing a chain that is internally
// perfect.
//
// A checkpoint defeats this without needing its signature checked, because it
// records the chain head as it stood when written. Rebuilding changes that
// head, so the committed value no longer matches. The signature defends
// against the next attack up -- an attacker who also re-signs the checkpoints
// with a key of their own -- which TestForgedLogWithoutKeyDetected covers.
func TestChainRebuildCaughtByCheckpoint(t *testing.T) {
	path, pub := writeLog(t, 12)
	rebuildChain(t, path, false)

	// Caught even without the public key: the checkpoint pins the old head.
	chainOnly, problems := verifyFile(t, path, nil)
	if chainOnly.Intact {
		t.Fatal("a rebuilt chain passed chain-only verification; " +
			"checkpoints are not pinning the head")
	}
	if len(problems) == 0 {
		t.Fatal("rebuild produced no problem")
	}

	// And caught with the key, reported the same way.
	res, problems := verifyFile(t, path, pub)
	if res.Intact {
		t.Fatal("a rebuilt chain passed verification with the public key")
	}

	found := false
	for _, p := range problems {
		if p.Kind == "checkpoint" {
			found = true
		}
	}
	if !found {
		t.Errorf("rebuild was not attributed to a checkpoint mismatch: %v", problems)
	}
}

// TestRebuildWithDroppedCheckpointLeavesAVisibleGap documents the honest limit
// of the scheme.
//
// An attacker who rebuilds the chain AND removes the checkpoints covering the
// edit produces a log that verifies -- but only up to the last surviving
// checkpoint. The records after it are chained and unanchored, and the
// verifier says so. The guarantee is not "tampering is impossible"; it is
// "tampering is either detected or confined to the unanchored tail, and the
// boundary is visible." An auditor who sees a large unanchored tail knows to
// distrust it.
func TestRebuildWithDroppedCheckpointLeavesAVisibleGap(t *testing.T) {
	path, pub := writeLog(t, 12)
	rebuildChain(t, path, true)

	res, _ := verifyFile(t, path, pub)

	if res.SignedThrough >= res.HeadSeq {
		t.Fatalf("dropping the trailing checkpoint should leave records unanchored: "+
			"signed through %d of %d", res.SignedThrough, res.HeadSeq)
	}
	if res.HeadSeq-res.SignedThrough == 0 {
		t.Error("the unanchored tail should be reported so an auditor can see it")
	}
}

// ---------------------------------------------------------------------------
// Evidence export
// ---------------------------------------------------------------------------

func exportBundle(t *testing.T, path string, pub ed25519.PublicKey, filter evidence.ExportFilter) *evidence.Bundle {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	b, err := evidence.Export(f, pub, "gw-test", filter, time.Now().UTC())
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return b
}

func TestUnfilteredExportIsContiguousAndVerifies(t *testing.T) {
	path, pub := writeLog(t, 12)

	b := exportBundle(t, path, pub, evidence.ExportFilter{})
	if len(b.Records) != 12 {
		t.Fatalf("exported %d records, want 12", len(b.Records))
	}
	if !b.Continuity.Complete {
		t.Error("an unfiltered export was not marked contiguous")
	}

	problems, err := evidence.VerifyBundle(b, pub)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if len(problems) != 0 {
		t.Errorf("clean bundle reported problems: %v", problems)
	}
}

// TestTamperedBundleDetected: an altered record inside an exported bundle must
// be caught, or a bundle would be weaker evidence than the log it came from.
func TestTamperedBundleDetected(t *testing.T) {
	path, pub := writeLog(t, 8)
	b := exportBundle(t, path, pub, evidence.ExportFilter{})

	b.Records[3].Event.Decision = "deny"

	problems, err := evidence.VerifyBundle(b, pub)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if len(problems) == 0 {
		t.Fatal("an altered record in a bundle was not detected")
	}
}

// TestFilteredExportDeclaresItsLimitation is an honesty property: a filtered
// extract cannot prove nothing was omitted, and must say so rather than let a
// recipient assume otherwise during a dispute.
func TestFilteredExportDeclaresItsLimitation(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	held, err := signer.FromKey(priv, "gw-test")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
		Path: path, Signer: held, KeyID: "gw-test", CheckpointEvery: 100,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	// Two agents interleaved, so filtering to one leaves gaps.
	for i := 0; i < 10; i++ {
		agent := "agent-a"
		if i%2 == 1 {
			agent = "agent-b"
		}
		if _, err := sink.Write(context.Background(), "gateway.request.allowed",
			evidence.GatewayEvent{AgentID: agent, TenantID: "t", Decision: "allow"}); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	_ = sink.Close()

	b := exportBundle(t, path, pub, evidence.ExportFilter{AgentID: "agent-a"})

	if len(b.Records) != 5 {
		t.Fatalf("filtered export has %d records, want 5", len(b.Records))
	}
	if b.Continuity.Complete {
		t.Error("a filtered extract was marked contiguous; a recipient could " +
			"wrongly conclude no record was omitted")
	}

	var warned bool
	for _, line := range b.Instructions {
		if strings.Contains(line, "FILTERED") {
			warned = true
		}
	}
	if !warned {
		t.Error("the bundle does not warn that a filtered extract cannot rule out omissions")
	}

	// Records present must still verify individually.
	problems, err := evidence.VerifyBundle(b, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(problems) != 0 {
		t.Errorf("filtered bundle reported problems: %v", problems)
	}
}

// TestBundleCarriesContinuityToTheWiderChain: a partial export must not be
// mistakable for a complete log.
func TestBundleCarriesContinuityToTheWiderChain(t *testing.T) {
	path, pub := writeLog(t, 10)
	b := exportBundle(t, path, pub, evidence.ExportFilter{})

	if b.Continuity.SourceHeadSeq != 10 {
		t.Errorf("source head seq = %d, want 10", b.Continuity.SourceHeadSeq)
	}
	if b.Continuity.PrevHash == "" {
		t.Error("bundle does not record what the first record links back to")
	}
	if b.VerificationKey == "" {
		t.Error("bundle carries no verification key")
	}
	if len(b.Instructions) == 0 {
		t.Error("bundle carries no verification instructions")
	}
}

// TestWriteDemoLog emits a realistic evidence log for manual inspection and
// for exercising the ags CLI. Skipped unless AGW_DEMO_LOG is set, so it never
// runs in CI.
//
// It lives here rather than in a helper binary because the sink is internal:
// anything outside this module cannot construct one, and adding an
// export-a-demo-log command to the CLI would be shipping test scaffolding to
// users.
func TestWriteDemoLog(t *testing.T) {
	path := os.Getenv("AGW_DEMO_LOG")
	if path == "" {
		t.Skip("set AGW_DEMO_LOG to write a demo evidence log")
	}
	keyPath := os.Getenv("AGW_DEMO_KEY")
	if keyPath == "" {
		t.Fatal("set AGW_DEMO_KEY to the base64 private key path")
	}

	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	priv, err := keys.DecodePrivateKey(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	held, err := signer.FromKey(priv, "gw-demo")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
		Path: path, Signer: held, KeyID: "gw-demo", CheckpointEvery: 6,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	base := time.Now().UTC().Add(-3 * time.Hour)
	for i := 0; i < 14; i++ {
		agent, action := "refund-agent", "billing.refund.create"
		decision, reason, status := "allow", "allowed", 200

		if i%5 == 4 {
			agent, action = "support-agent", "github.issue.create"
		}
		if i == 11 {
			decision, reason, status = "deny", "policy_denied", 403
		}

		at := base.Add(time.Duration(i) * 11 * time.Minute)
		if _, err := sink.Write(context.Background(), "gateway.request."+decision,
			evidence.GatewayEvent{
				EventID: fmt.Sprintf("evt_%02d", i), TenantID: "acme-bank",
				AgentID: agent, DecisionID: fmt.Sprintf("dec_%03d", i),
				Action: action, ResourceID: "acme/billing",
				ResourceType: "billing_account", Risk: "write",
				Decision: decision, ReasonCode: reason, HTTPStatus: status,
				StartedAt: at, FinishedAt: at.Add(12 * time.Millisecond),
			}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("wrote demo evidence log to %s", path)
}

// TestConcurrentWritesProduceAValidChain covers the group-commit
// implementation.
//
// Batching fsync across concurrent writers is exactly the kind of change that
// introduces a subtle ordering bug: a record appended under one lock and made
// durable under another must still land in sequence, link correctly, and
// appear exactly once. A chain that verifies only under single-threaded load
// would be worthless.
func TestConcurrentWritesProduceAValidChain(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	held, err := signer.FromKey(priv, "gw-conc")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
		Path: path, Signer: held, KeyID: "gw-conc", CheckpointEvery: 25,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	const (
		writers = 24
		each    = 25
	)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		seqs = map[uint64]int{}
		errs []error
	)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rec, err := sink.Write(context.Background(), "gateway.request.allowed",
					evidence.GatewayEvent{
						EventID:  fmt.Sprintf("w%d-%d", id, i),
						TenantID: "t", AgentID: fmt.Sprintf("agent-%d", id),
						Decision: "allow", ReasonCode: "allowed",
					})

				mu.Lock()
				if err != nil {
					errs = append(errs, err)
				} else {
					seqs[rec.Seq]++
				}
				mu.Unlock()
			}
		}(w)
	}

	wg.Wait()
	if err := sink.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, err := range errs {
		t.Errorf("concurrent write failed: %v", err)
	}

	// Every sequence must be handed out exactly once.
	expected := writers * each
	if len(seqs) != expected {
		t.Errorf("got %d distinct sequences, want %d", len(seqs), expected)
	}
	for seq, count := range seqs {
		if count != 1 {
			t.Errorf("sequence %d was returned %d times", seq, count)
		}
	}
	for i := uint64(1); i <= uint64(expected); i++ {
		if seqs[i] != 1 {
			t.Errorf("sequence %d is missing from the returned records", i)
			break
		}
	}

	// And the file itself must be an intact chain.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	res, problems, err := evidence.Verify(f, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Intact {
		t.Fatalf("concurrent writes produced a broken chain: %v", problems)
	}
	if res.Records != uint64(expected) {
		t.Errorf("log holds %d records, want %d", res.Records, expected)
	}
}

// TestWriteReturnsOnlyAfterDurability guards the property group commit must
// not weaken: when Write returns, that record is on disk. If it returned
// early, the gateway would forward a request whose decision a crash could
// still discard -- silently defeating fail-closed audit.
func TestWriteReturnsOnlyAfterDurability(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	held, err := signer.FromKey(priv, "gw-dur")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	path := filepath.Join(t.TempDir(), "decisions.jsonl")
	sink, err := evidence.NewEvidenceSink(evidence.EvidenceSinkConfig{
		Path: path, Signer: held, KeyID: "gw-dur", CheckpointEvery: 1000,
	})
	if err != nil {
		t.Fatalf("sink: %v", err)
	}

	// Write, then read the file back WITHOUT closing the sink. Anything still
	// sitting in a buffer would be missing.
	for i := 0; i < 20; i++ {
		rec, err := sink.Write(context.Background(), "gateway.request.allowed",
			evidence.GatewayEvent{EventID: fmt.Sprintf("e%d", i), Decision: "allow"})
		if err != nil {
			t.Fatalf("write: %v", err)
		}

		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		res, _, err := evidence.Verify(f, pub)
		_ = f.Close()
		if err != nil {
			t.Fatalf("verify: %v", err)
		}

		if res.HeadSeq < rec.Seq {
			t.Fatalf("Write returned seq %d but only %d is on disk; "+
				"a crash here would lose a decision the gateway already acted on",
				rec.Seq, res.HeadSeq)
		}
	}

	_ = sink.Close()
}
