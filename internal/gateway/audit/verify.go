package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"time"
)

// VerifyResult reports what an evidence log proved.
type VerifyResult struct {
	Records     uint64
	Checkpoints uint64

	FirstAt time.Time
	LastAt  time.Time

	HeadSeq  uint64
	HeadHash string

	// SignedThrough is the highest sequence covered by a verified
	// checkpoint. Records after it are chained but not yet anchored in time,
	// so they carry a weaker guarantee.
	SignedThrough uint64

	// UnanchoredRecords is how many records sit after the last verified
	// checkpoint.
	//
	// It is not a defect on its own -- a live log always has a tail that the
	// next checkpoint has not reached yet. It matters because those records
	// are the ONLY ones an attacker can remove without detection: everything
	// a checkpoint covers is pinned by a signature they do not hold, and
	// everything after it is pinned by nothing. A verifier that does not
	// report this number lets a caller say "verified" about a file whose
	// most recent activity could have been deleted.
	UnanchoredRecords uint64

	Intact bool
}

// VerifyProblem locates a break precisely, because "the log is invalid" is not
// actionable during an investigation. Knowing that record 4,812 was altered
// tells an investigator where to look and what remains trustworthy.
type VerifyProblem struct {
	Seq    uint64
	Kind   string
	Detail string
}

func (p VerifyProblem) Error() string {
	return fmt.Sprintf("record %d: %s: %s", p.Seq, p.Kind, p.Detail)
}

// Verify walks an evidence log and checks its integrity.
//
// pub may be nil to check chain consistency only. Supplying the gateway's
// public key additionally verifies the checkpoints, which is what makes the
// result meaningful against an adversary who could rewrite the file.
//
// The verifier deliberately depends on nothing but the log and the public key:
// an auditor must be able to run it without access to the gateway, the
// database, or anything else the vendor controls. Evidence that only the
// vendor can verify is not evidence.
func Verify(r io.Reader, pub ed25519.PublicKey) (*VerifyResult, []VerifyProblem, error) {
	return VerifyWithAnchor(r, pub, nil)
}

// VerifyWithAnchor is Verify, plus a checkpoint the auditor already holds.
//
// It exists because of a gap the gym made concrete. Truncating a log exactly
// at a checkpoint boundary leaves a shorter log that is perfectly consistent:
// every record chains, every remaining checkpoint verifies, and the records
// that named what the agent did last are gone. No amount of care inside the
// file can detect that, because the file is the thing being edited.
//
// The way out is one piece of state from outside it. An auditor who kept any
// earlier checkpoint -- mailed to them, published to a transparency log,
// written to object storage with retention -- can detect the rollback: the
// log must still contain that checkpoint, with that hash, and must extend at
// least that far. A single 200-byte line held anywhere the operator cannot
// reach turns "trust the file" into "prove it against something you kept".
//
// anchor may be nil, which is ordinary verification.
func VerifyWithAnchor(r io.Reader, pub ed25519.PublicKey, anchor *Checkpoint) (*VerifyResult, []VerifyProblem, error) {
	var (
		res      = &VerifyResult{Intact: true, HeadHash: GenesisHash}
		problems []VerifyProblem
		expected = GenesisHash
		lastSeq  uint64

		// Every checkpoint this log contains, so an anchor can be looked up
		// rather than searched for twice.
		seen = make(map[uint64]string)
	)

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		// Whitespace-only lines are skipped, not reported (RFC-0009 §1): they
		// carry no data, and an editor that leaves trailing spaces has not
		// tampered with anything.
		raw := bytes.Trim(scanner.Bytes(), " \t\r\n\v\f")
		if len(raw) == 0 {
			continue
		}

		rec, cp, err := decodeLine(raw)
		if err != nil {
			problems = append(problems, VerifyProblem{
				Seq: lastSeq + 1, Kind: "malformed",
				Detail: fmt.Sprintf("line %d is not valid JSON: %v", lineNo, err),
			})
			res.Intact = false
			continue
		}

		if cp != nil {
			res.Checkpoints++
			seen[cp.Seq] = cp.Hash
			if err := verifyCheckpointAgainst(pub, *cp, expected, lastSeq); err != nil {
				problems = append(problems, VerifyProblem{
					Seq: cp.Seq, Kind: "checkpoint", Detail: err.Error(),
				})
				res.Intact = false
				continue
			}
			if pub != nil {
				res.SignedThrough = cp.Seq
			}
			continue
		}

		if rec.Version == ChainVersionV1 {
			// Verified under v1 rules, but v1 could not protect four fields,
			// so saying "verified" without qualification would overstate what
			// this log can support.
			problems = append(problems, VerifyProblem{
				Seq:  rec.Seq,
				Kind: "superseded_format",
				Detail: "record is " + ChainVersionV1 + ", whose hash did not cover " +
					"sourceTenant, federated, trustGrant or risk; those four fields are " +
					"not protected in this log",
			})
		} else if rec.Version != ChainVersion {
			problems = append(problems, VerifyProblem{
				Seq: rec.Seq, Kind: "version",
				Detail: fmt.Sprintf("record declares %q, verifier understands %q", rec.Version, ChainVersion),
			})
			res.Intact = false
			continue
		}

		// A sequence gap is how a deleted record shows up.
		if rec.Seq != lastSeq+1 {
			problems = append(problems, VerifyProblem{
				Seq: rec.Seq, Kind: "sequence",
				Detail: fmt.Sprintf("expected sequence %d, found %d: %d record(s) removed or reordered",
					lastSeq+1, rec.Seq, rec.Seq-lastSeq-1),
			})
			res.Intact = false
		}

		// A broken link is how an edited or inserted record shows up.
		if rec.PrevHash != expected {
			problems = append(problems, VerifyProblem{
				Seq: rec.Seq, Kind: "chain",
				Detail: fmt.Sprintf("prevHash %s does not match the previous record's hash %s",
					short(rec.PrevHash), short(expected)),
			})
			res.Intact = false
		}

		// A rewritten field with the links left alone shows up here.
		if got := ComputeHash(*rec); got != rec.Hash {
			problems = append(problems, VerifyProblem{
				Seq: rec.Seq, Kind: "content",
				Detail: fmt.Sprintf("record content was altered: hash is %s but its contents compute to %s",
					short(rec.Hash), short(got)),
			})
			res.Intact = false
		}

		if res.Records == 0 {
			res.FirstAt = rec.Timestamp
		}
		res.LastAt = rec.Timestamp
		res.Records++
		lastSeq = rec.Seq
		expected = rec.Hash
		res.HeadSeq = rec.Seq
		res.HeadHash = rec.Hash
	}

	if err := scanner.Err(); err != nil {
		return nil, problems, fmt.Errorf("read evidence log: %w", err)
	}

	// An anchor is only evidence if it is what it claims to be. Comparing
	// against an anchor nobody signed would let anyone who can hand the
	// auditor a line manufacture a "forked history" finding.
	if anchor != nil && pub != nil {
		if err := VerifyCheckpoint(pub, *anchor); err != nil || anchor.Version != ChainVersion {
			problems = append(problems, VerifyProblem{
				Seq:  anchor.Seq,
				Kind: "anchor_invalid",
				Detail: "the anchor is not a checkpoint signed by the given key, so it proves nothing " +
					"about this log and was not compared",
			})
			res.Intact = false
			anchor = nil
		}
	}

	if anchor != nil {
		switch got, ok := seen[anchor.Seq]; {
		case res.HeadSeq < anchor.Seq:
			// The log ends before a checkpoint we already hold. It has been
			// rolled back, and by exactly this much.
			problems = append(problems, VerifyProblem{
				Seq:  res.HeadSeq,
				Kind: "rollback",
				Detail: fmt.Sprintf(
					"the log ends at sequence %d but a checkpoint for sequence %d is held out of band: "+
						"%d record(s) have been removed",
					res.HeadSeq, anchor.Seq, anchor.Seq-res.HeadSeq),
			})
			res.Intact = false

		case !ok:
			// Long enough to contain the anchor, but it is not there. The
			// history was rewritten rather than shortened.
			problems = append(problems, VerifyProblem{
				Seq:  anchor.Seq,
				Kind: "missing_anchor",
				Detail: fmt.Sprintf(
					"no checkpoint for sequence %d, although the log reaches sequence %d: "+
						"the checkpoint held out of band is not in this log",
					anchor.Seq, res.HeadSeq),
			})
			res.Intact = false

		case got != anchor.Hash:
			// Same sequence, different head. Two different histories.
			problems = append(problems, VerifyProblem{
				Seq:  anchor.Seq,
				Kind: "forked",
				Detail: fmt.Sprintf(
					"checkpoint at sequence %d commits to head %s, but the checkpoint held out of "+
						"band commits to %s: these are two different histories",
					anchor.Seq, short(got), short(anchor.Hash)),
			})
			res.Intact = false
		}
	}

	if pub != nil {
		// Saturating: a reordered log can end on a record whose seq is
		// below the last verified checkpoint, and unsigned subtraction then
		// wrapped to about 1.8e19 "unanchored records". Found by running a
		// JavaScript implementation against this one.
		if res.HeadSeq > res.SignedThrough {
			res.UnanchoredRecords = res.HeadSeq - res.SignedThrough
		}

		// A log with no checkpoint at all is internally consistent and proves
		// nothing. Anyone who can write the file can delete its tail, or
		// rewrite it from genesis and recompute every hash, and this function
		// had no way to object -- it reported the same "verified" as for a
		// fully anchored log.
		//
		// Refusing it is the only honest answer when a key was supplied: the
		// caller asked whether the signatures hold, and there are none.
		if res.Checkpoints == 0 && res.Records > 0 {
			problems = append(problems, VerifyProblem{
				Seq:  res.HeadSeq,
				Kind: "unanchored",
				Detail: "the log contains no checkpoint, so nothing in it is pinned by a " +
					"signature: every record could have been rewritten or removed together " +
					"and the chain would still be self-consistent",
			})
			res.Intact = false
		}
	}

	return res, problems, nil
}

func verifyCheckpointAgainst(pub ed25519.PublicKey, cp Checkpoint, expectedHead string, lastSeq uint64) error {
	if cp.Version != ChainVersion {
		return fmt.Errorf("declares version %q, verifier understands %q", cp.Version, ChainVersion)
	}

	// A checkpoint must commit to the chain head as it stood when written. If
	// it does not, either the checkpoint or the records around it were moved.
	if cp.Seq != lastSeq {
		return fmt.Errorf("commits to sequence %d but the chain had reached %d", cp.Seq, lastSeq)
	}
	if cp.Hash != expectedHead {
		return fmt.Errorf("commits to head %s but the chain head is %s",
			short(cp.Hash), short(expectedHead))
	}

	if pub == nil {
		return nil // chain-only verification was requested
	}
	return VerifyCheckpoint(pub, cp)
}

func short(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12] + "…"
}

// ReadRecords returns every decision record in an evidence log, skipping
// checkpoints. It does not verify: callers wanting assurance should run
// Verify first, so that reading and proving stay separate concerns.
func ReadRecords(r io.Reader) ([]Record, error) {
	var out []Record

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	for scanner.Scan() {
		// Whitespace-only lines are skipped, not reported (RFC-0009 §1): they
		// carry no data, and an editor that leaves trailing spaces has not
		// tampered with anything.
		raw := bytes.Trim(scanner.Bytes(), " \t\r\n\v\f")
		if len(raw) == 0 {
			continue
		}
		rec, _, err := decodeLine(raw)
		if err != nil {
			return nil, fmt.Errorf("evidence log is malformed: %w", err)
		}
		if rec != nil {
			out = append(out, *rec)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read evidence log: %w", err)
	}
	return out, nil
}
