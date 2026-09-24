package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Evidence chain format version. It is written into every record so a verifier
// can refuse a log it does not understand rather than guessing.
const ChainVersion = "agw-evidence-v2"

// ChainVersionV1 is the superseded format.
//
// Its hash input omitted SourceTenant, Federated, TrustGrant and Risk, so
// those four fields could be edited in a v1 log without breaking
// verification. They are the federation attribution and the risk class --
// precisely the fields that answer "whose agent, from which organization, and
// how dangerous was it". A v1 log is still internally consistent and its
// other fields are still protected; it simply cannot speak to those four, and
// the verifier says so rather than pretending either way.
const ChainVersionV1 = "agw-evidence-v1"

// GenesisHash is the previous-hash of the first record in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one entry in the tamper-evident decision log.
//
// The point of the chain is that an audit log kept as an ordinary file is not
// evidence: anyone with write access can edit a line or delete one, and no
// reader can tell. Chaining each record to the hash of the one before it means
// any edit, deletion or reordering invalidates every record after it, and the
// break points at exactly where the tampering happened.
type Record struct {
	Version   string       `json:"v"`
	Seq       uint64       `json:"seq"`
	EventName string       `json:"eventName"`
	Timestamp time.Time    `json:"timestamp"`
	Event     GatewayEvent `json:"event"`

	// PrevHash is the Hash of record Seq-1, or GenesisHash for the first.
	PrevHash string `json:"prevHash"`

	// Hash covers this record's content AND PrevHash, which is what links
	// the chain. It is excluded from its own computation.
	Hash string `json:"hash"`
}

// Checkpoint is a signed commitment to the state of the chain at a point in
// time.
//
// The chain alone proves internal consistency, but not much else: anyone who
// can rewrite the whole file can recompute every hash and produce a perfectly
// consistent forgery. A checkpoint signed by a key the log writer does not
// hold -- or published somewhere append-only -- pins the chain head to a
// moment. History before a checkpoint cannot be rewritten without producing a
// head that no longer matches what was signed.
type Checkpoint struct {
	Version string `json:"v"`
	Type    string `json:"type"` // always "checkpoint"

	// Seq and Hash identify the chain head being committed to.
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`

	// Count is how many records this checkpoint covers.
	//
	// It is written as the chain sequence, which verifyCheckpointAgainst
	// already checks against the records it has read, so this field adds no
	// detection of its own today. Truncation of the tail is caught instead by
	// VerifyResult.UnanchoredRecords, and truncation before a checkpoint by
	// the sequence and head-hash checks. The field stays because it is part
	// of the signed input and removing it would be a format break.
	Count uint64 `json:"count"`

	IssuedAt time.Time `json:"issuedAt"`

	KeyID     string `json:"keyId"`
	Signature string `json:"signature"`
}

// canonicalRecordInput builds the exact bytes a record's hash covers.
//
// Built field by field rather than by marshalling the struct: the hash is the
// evidence, so its input must not change because a Go version reordered map
// iteration or a struct tag was edited. Every field is length-prefixed so no
// value can shift a field boundary and make two different records hash alike.
func canonicalRecordInput(r Record) []byte {
	var b strings.Builder

	// The version a record declares selects its own hash input, so a v1 log
	// keeps verifying against v1 rules rather than appearing tampered with
	// because the format moved on.
	version := r.Version
	if version == "" {
		version = ChainVersion
	}

	b.WriteString(version)
	b.WriteString("\n")

	write := func(s string) { fmt.Fprintf(&b, "%d:%s", len(s), s) }

	write(fmt.Sprintf("%d", r.Seq))
	write(r.PrevHash)
	write(r.EventName)
	write(r.Timestamp.UTC().Format(time.RFC3339Nano))

	e := r.Event
	for _, field := range []string{
		e.EventID, e.TenantID, e.AgentID, e.KeyID,
		e.DecisionID, e.RequestID, e.TraceID,
		e.RouteID, e.Action, e.ResourceType, e.ResourceID, e.BackendID,
		e.Decision, e.ReasonCode,
		fmt.Sprintf("%d", e.HTTPStatus),
		e.SourceIP, e.UserAgent,
		e.StartedAt.UTC().Format(time.RFC3339Nano),
		e.FinishedAt.UTC().Format(time.RFC3339Nano),
		fmt.Sprintf("%d", e.LatencyMS),
	} {
		write(field)
	}

	// Added in v2. These were absent from v1's input, which meant an edit to
	// any of them left the hash unchanged: a partner's actions could be
	// reassigned to another organization, a federated call could be made to
	// look local, and a destructive action's recorded risk could be lowered
	// to read -- all without breaking verification.
	//
	// TestHashCoversEveryEventField walks GatewayEvent by reflection and
	// fails if any field is missing here, so the next field added to the
	// struct cannot repeat this quietly.
	if version != ChainVersionV1 {
		write(e.SourceTenant)
		write(strconv.FormatBool(e.Federated))
		write(e.TrustGrant)
		write(e.Risk)
		write(e.Producer)
	}

	return []byte(b.String())
}

// ComputeHash returns the chain hash for a record.
func ComputeHash(r Record) string {
	sum := sha256.Sum256(canonicalRecordInput(r))
	return fmt.Sprintf("%x", sum)
}

// Link fills in Seq, PrevHash and Hash, returning the chained record.
func Link(r Record, seq uint64, prevHash string) Record {
	r.Version = ChainVersion
	r.Seq = seq
	r.PrevHash = prevHash
	r.Hash = ComputeHash(r)
	return r
}

// canonicalCheckpointInput builds the bytes a checkpoint signature covers.
func canonicalCheckpointInput(c Checkpoint) []byte {
	var b strings.Builder

	b.WriteString(ChainVersion)
	b.WriteString("/checkpoint\n")

	write := func(s string) { fmt.Fprintf(&b, "%d:%s", len(s), s) }

	write(fmt.Sprintf("%d", c.Seq))
	write(c.Hash)
	write(fmt.Sprintf("%d", c.Count))
	write(c.IssuedAt.UTC().Format(time.RFC3339Nano))
	write(c.KeyID)

	return []byte(b.String())
}

// SignCheckpoint commits to the current chain head.
func SignCheckpoint(priv ed25519.PrivateKey, keyID string, seq uint64, hash string, count uint64, issuedAt time.Time) (*Checkpoint, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("checkpoint: private key is %d bytes, want %d",
			len(priv), ed25519.PrivateKeySize)
	}

	c := Checkpoint{
		Version:  ChainVersion,
		Type:     "checkpoint",
		Seq:      seq,
		Hash:     hash,
		Count:    count,
		IssuedAt: issuedAt.UTC(),
		KeyID:    keyID,
	}
	c.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(priv, canonicalCheckpointInput(c)))

	return &c, nil
}

// VerifyCheckpoint checks a checkpoint signature.
func VerifyCheckpoint(pub ed25519.PublicKey, c Checkpoint) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("checkpoint: public key is %d bytes, want %d",
			len(pub), ed25519.PublicKeySize)
	}

	raw, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		return fmt.Errorf("checkpoint %d: signature is not valid base64: %w", c.Seq, err)
	}
	if !ed25519.Verify(pub, canonicalCheckpointInput(c), raw) {
		return fmt.Errorf("checkpoint at seq %d does not verify; "+
			"the log may have been rewritten after it was signed", c.Seq)
	}
	return nil
}

// decodeLine returns either a record or a checkpoint from one JSONL line.
func decodeLine(raw []byte) (*Record, *Checkpoint, error) {
	if err := checkIJSON(raw); err != nil {
		return nil, nil, err
	}
	// Classify by the member named exactly "type" (RFC-0009 §1). Decoding
	// into a struct would match "TYPE" or "Type" too -- encoding/json is
	// case-insensitive -- and read a record carrying one as a checkpoint,
	// where a verifier that follows the specification reads a record.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, nil, err
	}
	var typ string
	if t, ok := top["type"]; ok {
		_ = json.Unmarshal(t, &typ) // a non-string type is simply not "checkpoint"
	}

	if typ == "checkpoint" {
		// Required for the same reason as record members: a mangled key
		// would otherwise be read as seq 0 or the zero time and reported as
		// a signature failure at a sequence that does not exist.
		var present map[string]json.RawMessage
		if err := json.Unmarshal(raw, &present); err != nil {
			return nil, nil, err
		}
		for _, k := range checkpointMembers {
			if _, ok := present[k]; !ok {
				return nil, nil, fmt.Errorf("checkpoint has no %q member", k)
			}
		}
		if err := checkExactNames(present, checkpointMembers); err != nil {
			return nil, nil, err
		}
		if err := checkKinds(present, checkpointKinds, 0, true); err != nil {
			return nil, nil, err
		}
		var c Checkpoint
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, nil, err
		}
		return nil, &c, nil
	}

	// Every record member is required (RFC-0009 §2.1). encoding/json would
	// otherwise fill a missing member with its zero value, so a damaged
	// checkpoint -- say one whose "type" key was mangled -- would be counted
	// as a record with an empty timestamp and hash, and reported as three
	// downstream problems instead of one malformed line. An independent
	// verifier written from the specification disagreed, which is how this
	// was found.
	var present map[string]json.RawMessage
	if err := json.Unmarshal(raw, &present); err != nil {
		return nil, nil, err
	}
	for _, k := range recordMembers {
		if _, ok := present[k]; !ok {
			return nil, nil, fmt.Errorf("record has no %q member", k)
		}
	}
	// "type" is included: a record carrying "TYPE" is a line a
	// case-insensitive reader would take for a checkpoint.
	if err := checkExactNames(present, append(recordMembers, "type")); err != nil {
		return nil, nil, err
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(present["event"], &event); err != nil {
		return nil, nil, fmt.Errorf("event is not an object: %w", err)
	}
	if err := checkKinds(present, recordKinds, 0, true); err != nil {
		return nil, nil, err
	}
	if err := checkExactNames(event, eventMemberNames); err != nil {
		return nil, nil, err
	}
	// Only the defined event members are typed; the rest are ignored, like
	// any unknown member.
	defined := make(map[string]json.RawMessage, len(eventMemberNames))
	for _, n := range eventMemberNames {
		if v, ok := event[n]; ok {
			defined[n] = v
		}
	}
	if err := checkKinds(defined, eventKinds, kString, false); err != nil {
		return nil, nil, fmt.Errorf("event: %w", err)
	}

	var r Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, nil, err
	}
	return &r, nil, nil
}

// checkpointMembers are the members every checkpoint must carry.
var checkpointMembers = []string{"v", "type", "seq", "hash", "count", "issuedAt", "keyId", "signature"}

// recordMembers are the members every record must carry.
var recordMembers = []string{"v", "seq", "eventName", "timestamp", "event", "prevHash", "hash"}

// SignCheckpointWith commits to the chain head using a custody-agnostic
// signer, so checkpoints can be signed by a key this process does not hold.
func SignCheckpointWith(signer interface {
	Sign(message []byte) ([]byte, error)
	KeyID() string
}, keyID string, seq uint64, hash string, count uint64, issuedAt time.Time) (*Checkpoint, error) {
	if signer == nil {
		return nil, fmt.Errorf("checkpoint: no signer configured")
	}
	if keyID == "" {
		keyID = signer.KeyID()
	}

	c := Checkpoint{
		Version:  ChainVersion,
		Type:     "checkpoint",
		Seq:      seq,
		Hash:     hash,
		Count:    count,
		IssuedAt: issuedAt.UTC(),
		KeyID:    keyID,
	}

	sig, err := signer.Sign(canonicalCheckpointInput(c))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	c.Signature = base64.StdEncoding.EncodeToString(sig)
	return &c, nil
}
