package gym

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// generateCheckpointKey writes an Ed25519 keypair in the format the product's
// own keygen writes, and returns the public half.
func generateCheckpointKey(privPath, pubPath string) (ed25519.PublicKey, error) {
	kp, err := keys.Generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(kp.PrivateKey)), 0o600); err != nil {
		return nil, fmt.Errorf("gym: write checkpoint key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(kp.PublicKey)), 0o644); err != nil {
		return nil, fmt.Errorf("gym: write checkpoint pubkey: %w", err)
	}
	return kp.PublicKey, nil
}

// LoadChain reads every record from an evidence file.
func LoadChain(path string) ([]gwaudit.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return gwaudit.ReadRecords(f)
}

// VerifyChain verifies an evidence file exactly as an external auditor would:
// with the file and a public key, and no access to the system that wrote it.
func VerifyChain(path string, pub ed25519.PublicKey) (*gwaudit.VerifyResult, []gwaudit.VerifyProblem, error) {
	return VerifyChainWithAnchor(path, pub, nil)
}

// VerifyChainWithAnchor is VerifyChain for an auditor who also kept a
// checkpoint from an earlier reading of the log.
func VerifyChainWithAnchor(path string, pub ed25519.PublicKey, anchor *gwaudit.Checkpoint) (*gwaudit.VerifyResult, []gwaudit.VerifyProblem, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return gwaudit.VerifyWithAnchor(f, pub, anchor)
}

// LastCheckpoint returns the final checkpoint in a log.
//
// This is what an auditor would have kept: a line copied out of a log they
// once read and verified, stored somewhere the operator of the log cannot
// reach. One line is enough to make the log's history non-repudiable from
// that point backwards.
func LastCheckpoint(path string) (*gwaudit.Checkpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var last *gwaudit.Checkpoint
	for _, line := range splitLines(raw) {
		if !isCheckpoint(line) {
			continue
		}
		var cp gwaudit.Checkpoint
		if err := json.Unmarshal(line, &cp); err != nil {
			continue
		}
		c := cp
		last = &c
	}
	if last == nil {
		return nil, fmt.Errorf("gym: %s contains no checkpoint", path)
	}
	return last, nil
}

// TamperKind names one way of altering an evidence file.
type TamperKind string

const (
	// TamperEditField rewrites a decision from deny to allow. The most
	// valuable forgery there is: it makes a refused action look permitted.
	TamperEditField TamperKind = "flip_decision_to_allow"

	// TamperDeleteRecord removes a record from the middle. Anyone covering
	// their tracks deletes rather than edits.
	TamperDeleteRecord TamperKind = "delete_middle_record"

	// TamperTruncate drops the tail, which is what a process killed at the
	// wrong moment also looks like -- so the verifier has to tell the two
	// apart using the checkpoint's record count.
	TamperTruncate TamperKind = "truncate_tail"

	// TamperReorder swaps two adjacent records without changing either.
	TamperReorder TamperKind = "reorder_adjacent"

	// TamperRehash rewrites a record AND recomputes every hash after it, so
	// the chain is internally consistent again. Only the signed checkpoint
	// catches this, which is precisely why checkpoints exist.
	TamperRehash TamperKind = "rewrite_and_rechain"

	// TamperStripCheckpoint deletes the checkpoints, leaving a consistent but
	// unpinned chain. A verifier given no key cannot object; one given a key
	// must.
	TamperStripCheckpoint TamperKind = "strip_checkpoints"

	// TamperTruncateAfterCheckpoint removes only the records written since
	// the last checkpoint. Every checkpoint still verifies; the most recent
	// activity is gone.
	TamperTruncateAfterCheckpoint TamperKind = "truncate_after_last_checkpoint"

	// TamperForeignCheckpoint replaces checkpoints with ones signed by a
	// different key -- the attacker's own.
	TamperForeignCheckpoint TamperKind = "checkpoint_signed_by_other_key"
)

// AllTampers is every alteration the gym attempts against a chain.
var AllTampers = []TamperKind{
	TamperEditField, TamperDeleteRecord, TamperTruncate, TamperTruncateAfterCheckpoint,
	TamperReorder, TamperRehash, TamperStripCheckpoint, TamperForeignCheckpoint,
}

// Tamper produces an altered copy of an evidence file.
//
// It works on the raw lines rather than on parsed records, because an attacker
// editing a log file has a text editor, not the product's own writer. Going
// through the writer would quietly re-derive fields that the attacker would
// have had to forge by hand, and the test would be easier than reality.
func Tamper(src, dst string, kind TamperKind) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	lines := splitLines(raw)
	if len(lines) < 4 {
		return fmt.Errorf("gym: chain too short to tamper (%d lines)", len(lines))
	}

	switch kind {
	case TamperEditField:
		i := findRecord(lines, func(m map[string]any) bool {
			return eventDecision(m) == "deny"
		})
		if i < 0 {
			return fmt.Errorf("gym: no deny record to flip")
		}
		lines[i] = replaceInJSON(lines[i], `"Decision":"deny"`, `"Decision":"allow"`)

	case TamperDeleteRecord:
		i := findRecord(lines, func(m map[string]any) bool { return true })
		if i < 0 {
			return fmt.Errorf("gym: no record to delete")
		}
		lines = append(lines[:i], lines[i+1:]...)

	case TamperTruncate:
		lines = lines[:len(lines)/2]

	case TamperReorder:
		i := findRecord(lines, func(m map[string]any) bool { return true })
		if i < 0 || i+1 >= len(lines) {
			return fmt.Errorf("gym: nothing to reorder")
		}
		lines[i], lines[i+1] = lines[i+1], lines[i]

	case TamperRehash:
		return rewriteAndRechain(lines, dst)

	case TamperTruncateAfterCheckpoint:
		return truncateAfterLastCheckpoint(lines, dst)

	case TamperStripCheckpoint:
		var kept [][]byte
		for _, l := range lines {
			if !isCheckpoint(l) {
				kept = append(kept, l)
			}
		}
		lines = kept

	case TamperForeignCheckpoint:
		return foreignCheckpoint(lines, dst)

	default:
		return fmt.Errorf("gym: unknown tamper %q", kind)
	}

	return os.WriteFile(dst, bytes.Join(append(lines, nil), []byte("\n")), 0o600)
}

// rewriteAndRechain flips a decision and then recomputes every subsequent
// hash, producing a chain that is internally perfect.
//
// This is the forgery the hash chain alone cannot detect, and building it here
// is how the gym proves the claim made for checkpoints rather than repeating
// it. It recomputes using the product's own canonical hashing, because a
// forgery that used a different hash input would fail for the wrong reason.
//
// The original checkpoints are KEPT. An earlier version of this dropped them,
// which made the forgery succeed -- but it succeeded by removing the control
// rather than by defeating it, which strip_checkpoints already measures.
// Keeping them is the harder attack and the one worth asking about: the
// attacker has the log but not the key.
func rewriteAndRechain(lines [][]byte, dst string) error {
	var records []gwaudit.Record
	var checkpoints [][]byte
	for _, l := range lines {
		if isCheckpoint(l) {
			checkpoints = append(checkpoints, l)
			continue
		}
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var r gwaudit.Record
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		records = append(records, r)
	}
	if len(records) == 0 {
		return fmt.Errorf("gym: no records to rechain")
	}

	flipped := false
	for i := range records {
		if !flipped && records[i].Event.Decision == "deny" {
			records[i].Event.Decision = "allow"
			records[i].Event.ReasonCode = "allowed"
			flipped = true
		}
	}
	if !flipped {
		records[0].Event.ReasonCode = "allowed"
	}

	// Relink from genesis using the product's own Link, so the forged chain
	// is hashed exactly the way a genuine one is. A forgery that used a
	// different hash input would be caught for the wrong reason and would
	// tell us nothing about whether checkpoints are load-bearing.
	prev := gwaudit.GenesisHash
	for i := range records {
		records[i] = gwaudit.Link(records[i], records[i].Seq, prev)
		prev = records[i].Hash
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	for _, cp := range checkpoints {
		buf.Write(cp)
		buf.WriteByte('\n')
	}
	return os.WriteFile(dst, buf.Bytes(), 0o600)
}

// truncateAfterLastCheckpoint removes only the records written since the last
// checkpoint, leaving every checkpoint in place.
//
// This is the precise version of the truncation attack, and the one an
// attacker would actually use: the chain stays consistent, every checkpoint
// still verifies against the head it committed to, and the records that named
// what the agent did last are simply gone.
func truncateAfterLastCheckpoint(lines [][]byte, dst string) error {
	last := -1
	for i, l := range lines {
		if isCheckpoint(l) {
			last = i
		}
	}
	if last < 0 {
		return fmt.Errorf("gym: chain has no checkpoint to truncate after")
	}
	if last == len(lines)-1 {
		// Everything is already covered. Drop the final checkpoint too, so
		// there is a tail to remove.
		for i := last - 1; i >= 0; i-- {
			if isCheckpoint(lines[i]) {
				last = i
				break
			}
		}
	}
	kept := lines[:last+1]
	return os.WriteFile(dst, bytes.Join(append(kept, nil), []byte("\n")), 0o600)
}

// foreignCheckpoint re-signs the chain head with a key the verifier has never
// seen, which is what an attacker who rewrote the log would have to do.
func foreignCheckpoint(lines [][]byte, dst string) error {
	var kept [][]byte
	var lastRecord gwaudit.Record
	var count uint64
	for _, l := range lines {
		if isCheckpoint(l) || len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		var r gwaudit.Record
		if err := json.Unmarshal(l, &r); err != nil {
			return err
		}
		lastRecord = r
		count++
		kept = append(kept, l)
	}

	kp, err := keys.Generate()
	if err != nil {
		return err
	}
	cp, err := gwaudit.SignCheckpoint(
		kp.PrivateKey, kp.KeyID, lastRecord.Seq, lastRecord.Hash, count, time.Now().UTC())
	if err != nil {
		return err
	}
	line, err := json.Marshal(cp)
	if err != nil {
		return err
	}
	kept = append(kept, line)
	return os.WriteFile(dst, bytes.Join(append(kept, nil), []byte("\n")), 0o600)
}

func splitLines(raw []byte) [][]byte {
	var out [][]byte
	for _, l := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(l)) == 0 {
			continue
		}
		out = append(out, append([]byte(nil), l...))
	}
	return out
}

func isCheckpoint(line []byte) bool {
	return bytes.Contains(line, []byte(`"type":"checkpoint"`))
}

func findRecord(lines [][]byte, pred func(map[string]any) bool) int {
	// Start at 1 so the genesis record is left alone: editing it is a
	// different (and more obvious) attack than editing history.
	for i := 1; i < len(lines); i++ {
		if isCheckpoint(lines[i]) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(lines[i], &m); err != nil {
			continue
		}
		if pred(m) {
			return i
		}
	}
	return -1
}

func eventDecision(m map[string]any) string {
	ev, ok := m["event"].(map[string]any)
	if !ok {
		return ""
	}
	d, _ := ev["Decision"].(string)
	return d
}

func replaceInJSON(line []byte, old, new string) []byte {
	return []byte(strings.Replace(string(line), old, new, 1))
}

// readPubKey loads a base64 Ed25519 public key as `agw keygen` writes it.
func readPubKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gym: read checkpoint public key: %w", err)
	}
	pub, err := keys.DecodePublicKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("gym: decode checkpoint public key: %w", err)
	}
	return pub, nil
}
