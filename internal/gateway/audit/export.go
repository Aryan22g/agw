package audit

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Bundle is a self-contained evidence package for an auditor.
//
// Self-contained is the point. An auditor should be able to verify the
// contents without access to the gateway, the database, the vendor, or a
// network — using only this file and a published verification procedure. An
// evidence package that requires calling the party being audited is not
// evidence.
type Bundle struct {
	Format  string `json:"format"`
	Version string `json:"version"`

	// Subject describes what was extracted and on whose authority.
	Subject BundleSubject `json:"subject"`

	// VerificationKey is the public half of the key that signed the
	// checkpoints, so a verifier need not obtain it separately.
	//
	// Including it does not make the bundle self-attesting: an auditor must
	// confirm this key out of band, exactly as they would a signing
	// certificate. It is here for convenience, and the field name says so.
	VerificationKey string `json:"verificationKey"`
	KeyID           string `json:"keyId"`

	// Records and Checkpoints are the extracted slice of the chain.
	Records     []Record     `json:"records"`
	Checkpoints []Checkpoint `json:"checkpoints"`

	// Continuity states how this slice connects to the wider chain, so a
	// partial extract cannot be mistaken for a complete log.
	Continuity BundleContinuity `json:"continuity"`

	// Instructions tell a recipient how to verify without reading code.
	Instructions []string `json:"howToVerify"`
}

// BundleSubject records what was asked for.
type BundleSubject struct {
	TenantID   string    `json:"tenantId,omitempty"`
	AgentID    string    `json:"agentId,omitempty"`
	From       time.Time `json:"from,omitempty"`
	To         time.Time `json:"to,omitempty"`
	ExportedAt time.Time `json:"exportedAt"`
}

// BundleContinuity describes where the extract sits in the chain.
type BundleContinuity struct {
	FirstSeq uint64 `json:"firstSeq"`
	LastSeq  uint64 `json:"lastSeq"`

	// PrevHash links the first exported record to the record before it.
	// A verifier holding the full log can confirm this extract was not
	// lifted from a different chain.
	PrevHash string `json:"prevHashOfFirstRecord"`

	// Complete is false when filters excluded records inside the range, so a
	// reader cannot mistake a filtered view for an unbroken sequence. A
	// filtered extract cannot be chain-verified on its own, and saying so is
	// more useful than letting someone discover it during a dispute.
	Complete bool `json:"isContiguous"`

	// SourceHead is the chain head at export time, so a recipient can tell
	// whether they were given everything up to the present.
	SourceHeadSeq  uint64 `json:"sourceHeadSeq"`
	SourceHeadHash string `json:"sourceHeadHash"`
}

// ExportFilter narrows an export.
type ExportFilter struct {
	TenantID string
	AgentID  string
	From     time.Time
	To       time.Time
}

// Export builds an evidence bundle from a log.
func Export(r io.Reader, pub ed25519.PublicKey, keyID string, filter ExportFilter, now time.Time) (*Bundle, error) {
	all, checkpoints, head, headHash, err := readAll(r)
	if err != nil {
		return nil, err
	}

	var (
		selected   []Record
		prevHash   string
		contiguous = true
		lastSeq    uint64
	)

	for _, rec := range all {
		if !matchesFilter(rec, filter) {
			continue
		}
		if len(selected) == 0 {
			prevHash = rec.PrevHash
		} else if rec.Seq != lastSeq+1 {
			// A gap means filtering removed records between these two, so
			// the extract is not a contiguous chain segment.
			contiguous = false
		}
		selected = append(selected, rec)
		lastSeq = rec.Seq
	}

	bundle := &Bundle{
		Format:  "agw-evidence-bundle",
		Version: ChainVersion,
		Subject: BundleSubject{
			TenantID: filter.TenantID, AgentID: filter.AgentID,
			From: filter.From, To: filter.To, ExportedAt: now.UTC(),
		},
		KeyID:       keyID,
		Records:     selected,
		Checkpoints: relevantCheckpoints(checkpoints, selected),
		Continuity: BundleContinuity{
			PrevHash:       prevHash,
			Complete:       contiguous,
			SourceHeadSeq:  head,
			SourceHeadHash: headHash,
		},
		Instructions: verificationInstructions(contiguous),
	}

	if len(selected) > 0 {
		bundle.Continuity.FirstSeq = selected[0].Seq
		bundle.Continuity.LastSeq = selected[len(selected)-1].Seq
	}
	if pub != nil {
		bundle.VerificationKey = base64.StdEncoding.EncodeToString(pub)
	}

	return bundle, nil
}

// VerifyBundle re-checks an exported bundle.
//
// A contiguous bundle is verified as a chain segment. A filtered one cannot
// be: the hashes of excluded records are missing, so only per-record content
// hashes and checkpoint signatures can be confirmed. That limitation is
// reported rather than hidden.
func VerifyBundle(b *Bundle, pub ed25519.PublicKey) ([]VerifyProblem, error) {
	if b == nil {
		return nil, fmt.Errorf("bundle: nil")
	}
	if b.Version != ChainVersion {
		return nil, fmt.Errorf("bundle: version %q, verifier understands %q", b.Version, ChainVersion)
	}

	var problems []VerifyProblem

	// Per-record content hashes hold regardless of contiguity.
	for _, rec := range b.Records {
		if got := ComputeHash(rec); got != rec.Hash {
			problems = append(problems, VerifyProblem{
				Seq: rec.Seq, Kind: "content",
				Detail: fmt.Sprintf("record content was altered: hash is %s but contents compute to %s",
					short(rec.Hash), short(got)),
			})
		}
	}

	// Chain links only mean something across a contiguous extract.
	if b.Continuity.Complete {
		expected := b.Continuity.PrevHash
		for _, rec := range b.Records {
			if rec.PrevHash != expected {
				problems = append(problems, VerifyProblem{
					Seq: rec.Seq, Kind: "chain",
					Detail: fmt.Sprintf("prevHash %s does not match %s",
						short(rec.PrevHash), short(expected)),
				})
			}
			expected = rec.Hash
		}
	}

	if pub != nil {
		for _, cp := range b.Checkpoints {
			if err := VerifyCheckpoint(pub, cp); err != nil {
				problems = append(problems, VerifyProblem{
					Seq: cp.Seq, Kind: "checkpoint", Detail: err.Error(),
				})
			}
		}
	}

	return problems, nil
}

func matchesFilter(rec Record, f ExportFilter) bool {
	if f.TenantID != "" && rec.Event.TenantID != f.TenantID && rec.Event.SourceTenant != f.TenantID {
		return false
	}
	if f.AgentID != "" && rec.Event.AgentID != f.AgentID {
		return false
	}
	if !f.From.IsZero() && rec.Timestamp.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && rec.Timestamp.After(f.To) {
		return false
	}
	return true
}

// relevantCheckpoints keeps checkpoints covering the exported range, plus the
// first one after it -- which is what anchors the final records in time.
func relevantCheckpoints(all []Checkpoint, records []Record) []Checkpoint {
	if len(records) == 0 {
		return nil
	}
	first := records[0].Seq
	last := records[len(records)-1].Seq

	var out []Checkpoint
	for _, cp := range all {
		if cp.Seq >= first-1 && cp.Seq <= last {
			out = append(out, cp)
			continue
		}
		if cp.Seq > last {
			out = append(out, cp)
			break
		}
	}
	return out
}

func verificationInstructions(contiguous bool) []string {
	base := []string{
		"1. Obtain the gateway's public key independently of this file. The " +
			"verificationKey field is a convenience, not proof.",
		"2. Run: ags audit verify-bundle -bundle <this file> -public-key <key>",
		"3. Each record's hash covers its own contents, so any altered field " +
			"is detected regardless of anything else.",
		"4. Each checkpoint is signed by the gateway's key and commits to the " +
			"chain head at the time it was written.",
	}
	if contiguous {
		return append(base,
			"5. This extract is contiguous: records form an unbroken hash chain, "+
				"so a removed record would also be detected.")
	}
	return append(base,
		"5. This extract is FILTERED and therefore not contiguous. Individual "+
			"records and checkpoint signatures verify, but removal of a record "+
			"excluded by the filter cannot be detected from this file alone. "+
			"Request an unfiltered export to check for omissions.")
}

func readAll(r io.Reader) ([]Record, []Checkpoint, uint64, string, error) {
	var (
		records     []Record
		checkpoints []Checkpoint
		head        uint64
		headHash    = GenesisHash
	)

	dec := json.NewDecoder(r)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, 0, "", fmt.Errorf("read evidence log: %w", err)
		}

		rec, cp, err := decodeLine(raw)
		if err != nil {
			return nil, nil, 0, "", fmt.Errorf("evidence log is malformed: %w", err)
		}
		if cp != nil {
			checkpoints = append(checkpoints, *cp)
			continue
		}
		records = append(records, *rec)
		head = rec.Seq
		headHash = rec.Hash
	}

	return records, checkpoints, head, headHash, nil
}
