# RFC-0009: Evidence Chain Format (`agw-evidence-v2`)

## Status

Draft. Describes the format every producer in this repository writes today:
the confinement proxy and firewall, the MCP enforcement point, the gateway,
and the OpenTelemetry recorder.

Conformance corpus: [`conformance/evidence/agw-evidence-v2.json`](../../conformance/evidence/agw-evidence-v2.json).
Independent implementation: [`cmd/agw-verify`](../../cmd/agw-verify), written
from this document, standard library only, and required to pass the corpus.

## Why this document exists

The claim the product rests on is that anyone can check the evidence without
trusting whoever produced it. That claim is only as good as the ability of a
stranger to write their own verifier. A format whose only complete description
is the reference implementation's source code fails that test, however good
the code is.

This document is written so that it can be implemented without reading any
code in this repository. `cmd/agw-verify` exists to prove that it can: it was
written against this text, imports nothing from the rest of the repository,
and a test fails if it ever does.

## Conventions

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

`len(s)` is the length of a string **in bytes** of its UTF-8 encoding, not in
characters. `dec(n)` is the base-10 ASCII representation of an integer with no
sign for non-negative values, no leading zeros, and `0` for zero. `||` is
concatenation.

## 1. File format

An evidence log is a UTF-8 text file of lines separated by `\n` (LF). Each
non-empty line is one JSON object (RFC 8259). Before anything else, a
verifier trims ASCII whitespace -- space, tab, CR, LF, VT, FF, and nothing
else -- from both ends of each line, and ignores a line that is then empty. A
trailing newline is permitted and expected.

Two kinds of line share one file, so the evidence is a single artifact:

- a **checkpoint** is an object whose `type` member is the string
  `"checkpoint"`;
- every other object is a **record**.

A reader MUST classify a line by the member named exactly `type` and nothing
else. A `type` whose value is not the string `"checkpoint"` makes the line a
record, on which `type` is an unknown member.

Every object on a line MUST be valid I-JSON (RFC 7493): in particular, no
object at any depth may contain the same member name twice. A verifier MUST
treat a line that violates this as `malformed`. The rule is not pedantry. JSON
parsers disagree about duplicates -- some keep the first value, most keep the
last -- so a record with `"Decision":"allow"` followed by `"Decision":"deny"`
could be hashed as a denial by the verifier and shown as an allow by whatever
tool a reviewer used to read it. Refusing duplicates removes the disagreement.

Member names are case-sensitive, and a member whose name equals a name this
document defines **except for letter case** (`decision` beside `Decision`)
MUST also make the line `malformed`. Some widely used JSON libraries, Go's
among them, match member names case-insensitively; others do not. Without this
rule a genuine `{"Decision":"allow"}` rewritten as
`{"Decision":"deny", …, "decision":"allow"}` hashes as `allow` in one
implementation -- and verifies -- while displaying as `deny` in another. The
duplicate-member rule does not catch it, because the two names are different
strings. For a record, `type` counts as a defined name: a record
carrying `TYPE` or `Type` is `malformed`, because a case-insensitive reader
would take it for a checkpoint.

## 2. Records

### 2.1 Members

| Member | JSON type | Meaning |
|---|---|---|
| `v` | string | Format version: `"agw-evidence-v2"`, or `"agw-evidence-v1"` for the superseded format (§3). |
| `seq` | integer | Position in the chain, starting at 1, increasing by exactly 1. |
| `eventName` | string | What kind of event this is, e.g. `confine.egress.denied`. |
| `timestamp` | timestamp | When the record was written (§2.3). |
| `event` | object | The decision or observation. §2.2. |
| `prevHash` | string | The `hash` of record `seq - 1`, or the genesis value for `seq` 1. |
| `hash` | string | This record's hash. §3. |

Every member in this table is REQUIRED. A line that is not a checkpoint and
lacks any of them is not a record, and a verifier MUST report it as
`malformed` rather than supply defaults: a damaged checkpoint whose `type` was
mangled must read as one malformed line, not as a record with an empty
timestamp producing three unrelated findings.

The genesis value is sixty-four ASCII `0` characters.

Unknown members MUST be ignored by a verifier and are not covered by the hash.
A producer MUST NOT rely on an unknown member being protected.

### 2.2 The `event` object

The member names are case-sensitive and are exactly as below. A producer MUST
write every member. A verifier MUST treat a missing or `null` member as its zero value -- the empty
string, `0`, `false`, or the zero time (§2.3) -- which is what it hashes as.
Members this table does not define are ignored.

| # | Member | JSON type | Hashed in |
|---|---|---|---|
| 1 | `EventID` | string | v1, v2 |
| 2 | `TenantID` | string | v1, v2 |
| 3 | `AgentID` | string | v1, v2 |
| 4 | `KeyID` | string | v1, v2 |
| 5 | `DecisionID` | string | v1, v2 |
| 6 | `RequestID` | string | v1, v2 |
| 7 | `TraceID` | string | v1, v2 |
| 8 | `RouteID` | string | v1, v2 |
| 9 | `Action` | string | v1, v2 |
| 10 | `ResourceType` | string | v1, v2 |
| 11 | `ResourceID` | string | v1, v2 |
| 12 | `BackendID` | string | v1, v2 |
| 13 | `Decision` | string | v1, v2 |
| 14 | `ReasonCode` | string | v1, v2 |
| 15 | `HTTPStatus` | integer | v1, v2 |
| 16 | `SourceIP` | string | v1, v2 |
| 17 | `UserAgent` | string | v1, v2 |
| 18 | `StartedAt` | string (timestamp) | v1, v2 |
| 19 | `FinishedAt` | string (timestamp) | v1, v2 |
| 20 | `LatencyMS` | integer | v1, v2 |
| 21 | `SourceTenant` | string | v2 only |
| 22 | `Federated` | boolean | v2 only |
| 23 | `TrustGrant` | string | v2 only |
| 24 | `Risk` | string | v2 only |
| 25 | `Producer` | string | v2 only |

The order in the table is the order in which fields enter the hash (§3). It
is **not** the order members appear in the JSON, which is irrelevant.

`Producer` names what wrote the record. Values beginning `enforced:` come from
an enforcement point the workload cannot bypass; values beginning `observed:`
record what the workload reported about itself and are not evidence that
anything was enforced. Defined values are `enforced:confine-proxy`,
`enforced:confine-firewall`, `enforced:mcp`, `enforced:gateway` and
`observed:recorder`.

### 2.3 Timestamps

Timestamps are hashed in a normalised form, `TS(t)`, not as they appear in the
JSON. This matters: two spellings of one instant — `…T16:16:34.5+05:30` and
`…T10:46:34.5Z` — must hash identically, and a verifier that hashed the JSON
text would reject a valid record written by a producer that used an offset.

A timestamp MUST match this grammar exactly:

```
timestamp = date "T" time [ "." 1*9DIGIT ] zone
date      = 4DIGIT "-" 2DIGIT "-" 2DIGIT        ; a real proleptic Gregorian date
time      = 2DIGIT ":" 2DIGIT ":" 2DIGIT        ; hh 00-23, mm 00-59, ss 00-59
zone      = "Z" / ( "+" / "-" ) 2DIGIT ":" 2DIGIT   ; hh 00-23, mm 00-59
```

`T` and `Z` are uppercase; the fraction separator is `.`; at most nine
fractional digits. This is a strict subset of RFC 3339, and it is spelled out
because "RFC 3339" alone was not enough: common parsers accept a comma before
the fraction, an offset of `+24:00`, or more than nine digits, and some reject
the lowercase `t` and `z` that RFC 3339 allows. Two verifiers that each "parse
RFC 3339" disagreed on exactly those inputs. Every producer writes this form.
A timestamp that does not match is `malformed`.

`TS(t)` is:

1. Check the grammar above.
2. Convert to UTC by subtracting the offset.
3. Format as `YYYY-MM-DDTHH:MM:SS`, zero-padded, followed by:
   - if the fractional seconds are zero: nothing;
   - otherwise: `.` and the fractional seconds to nanosecond precision (nine
     digits) **with trailing zeros removed**;
4. followed by `Z`.

Examples: `2026-09-23T16:16:34.392590Z` → `2026-09-23T16:16:34.39259Z`;
`2026-09-23T16:16:34.000000000Z` → `2026-09-23T16:16:34Z`;
`2026-09-23T21:46:34.5+05:30` → `2026-09-23T16:16:34.5Z`.

The zero time, used for an unknown timestamp, is `0001-01-01T00:00:00Z` and
normalises to itself.

### 2.4 JSON types

A member's value MUST have the JSON type stated for it:

- *string*: a JSON string;
- *integer*: a JSON number with no fraction and no exponent (`-?(0|[1-9][0-9]*)`),
  within the signed 64-bit range; `seq` and `count` MUST be non-negative and
  within the unsigned 64-bit range. A quoted number such as `"403"` is a
  string, not an integer;
- *boolean*: `true` or `false`;
- *timestamp*: a JSON string matching §2.3;
- *object*: a JSON object.

`null` is not a value of any of these types. For a record or checkpoint member
it is `malformed`; for an event member it is treated as absent (§2.2).

## 3. Record hash

The hash input `H(r)` for a record is:

```
H(r) = v || "\n" || F(dec(seq)) || F(prevHash) || F(eventName) || F(TS(timestamp))
         || F(e1) || F(e2) || ... || F(e20)
         [ || F(e21) || ... || F(e25) ]      -- only when v is "agw-evidence-v2"

F(s) = dec(len(s)) || ":" || s
```

where `e1` … `e25` are the event members in the order of §2.2, each converted
to a string as follows:

- strings: as-is;
- integers (`HTTPStatus`, `LatencyMS`): `dec(n)`, with a leading `-` for a
  negative value;
- booleans (`Federated`): `true` or `false`;
- timestamps (`StartedAt`, `FinishedAt`): `TS(t)`.

The length prefix on every field is what makes the encoding unambiguous: no
value, whatever it contains, can move a field boundary and make two different
records produce the same input.

The record's `hash` is the SHA-256 (FIPS 180-4) of `H(r)`, as 64 lowercase
hexadecimal characters.

Version `agw-evidence-v1` omitted fields 21–25. A v1 log still verifies under
v1 rules, but those five fields — federation attribution, risk class and
producer — are not protected in it, and a verifier MUST say so (§6, problem
`superseded_format`).

## 4. Checkpoints

A checkpoint is a signed commitment to the chain as it stood when it was
written. The chain alone proves internal consistency; anyone able to rewrite
the whole file can recompute every hash. A checkpoint signed by a key the
writer of the file does not control pins history up to it.

### 4.1 Members

| Member | JSON type | Meaning |
|---|---|---|
| `v` | string | MUST be `"agw-evidence-v2"`. |
| `type` | string | `"checkpoint"`. |
| `seq` | integer | The `seq` of the last record before this line. |
| `hash` | string | The `hash` of that record. |
| `count` | integer | Records covered. Equal to `seq` in every current producer. |
| `issuedAt` | timestamp | When it was signed (§2.3). |
| `keyId` | string | Identifies the signing key. Informative: verification uses the key the verifier was given, never one named here. |
| `signature` | string | Ed25519 signature, standard base64 with padding (RFC 4648 §4). |

Every member is REQUIRED; a checkpoint lacking one is `malformed`. Without
this rule a mangled `seq` key reads as zero and surfaces as a signature failure
at a sequence number that does not exist.

### 4.2 Signing input

```
C(c) = "agw-evidence-v2/checkpoint\n" || F(dec(seq)) || F(hash) || F(dec(count))
       || F(TS(issuedAt)) || F(keyId)
```

`signature` is the Ed25519 (RFC 8032, pure, not Ed25519ph) signature over
`C(c)`.

### 4.3 Public keys

A public key is the 32-byte Ed25519 public key, encoded as standard base64
with padding (44 characters). Key files written by `agw keygen` and `agw init`
contain exactly that, optionally followed by a newline.

The key id producers write is the RFC 7638 JWK thumbprint of the key as an
`OKP`/`Ed25519` JWK, base64url without padding. A verifier does not need it.

## 5. Anchors

An **anchor** is a checkpoint line the verifier obtained from somewhere other
than the log being verified — an earlier copy of the log, a message sent to an
auditor at the time, a transparency log, object storage with retention.

Anchors exist because one edit is invisible to any check made from inside the
file: truncating the log exactly after a checkpoint leaves a shorter log in
which every record chains and every checkpoint verifies. Nothing in the file
records that there used to be more. Only state the attacker could not edit can.

## 6. Verification

A verifier takes a log, OPTIONALLY an Ed25519 public key, and OPTIONALLY an
anchor. It MUST NOT use the network, and MUST NOT need anything but these
inputs.

### 6.1 State

```
expected   = genesis value          -- the hash the next record must link to
lastSeq    = 0
records    = 0,  checkpoints = 0
signedThrough = 0
intact     = true
seen       = {}                     -- checkpoint seq -> hash
```

### 6.2 Per line, in file order

For each non-empty line:

1. If it is not a JSON object, violates §1's duplicate-member rule, is a
   record or checkpoint lacking a required member (§2.1, §4.1), has a member of the wrong JSON
   type, or has a timestamp that is not RFC 3339:
   problem `malformed`, `intact = false`, next line.

2. **Checkpoint** (`type` is `"checkpoint"`):
   1. `checkpoints += 1`; `seen[seq] = hash`.
   2. If `v` is not `"agw-evidence-v2"`: problem `checkpoint`, `intact = false`, next line.
   3. If `seq ≠ lastSeq`: problem `checkpoint`, `intact = false`, next line.
   4. If `hash ≠ expected`: problem `checkpoint`, `intact = false`, next line.
   5. If a key was given and the signature does not verify under it over
      `C(c)`: problem `checkpoint`, `intact = false`, next line.
   6. If a key was given: `signedThrough = seq`.

3. **Record**:
   1. If `v` is `"agw-evidence-v1"`: problem `superseded_format` (this does
      **not** clear `intact`). Otherwise, if `v` is not `"agw-evidence-v2"`
      (including absent or empty): problem `version`, `intact = false`, next
      line.
   2. If `seq ≠ lastSeq + 1`: problem `sequence`, `intact = false`.
   3. If `prevHash ≠ expected`: problem `chain`, `intact = false`.
   4. If `SHA-256(H(r)) ≠ hash`: problem `content`, `intact = false`.
   5. `records += 1`; `lastSeq = seq`; `expected = hash` (the value in the
      record, as written); `headSeq = seq`.

   Steps 3.2–3.4 are all evaluated; one record may produce several problems.

### 6.3 After the last line

4. If an anchor and a key were given, and the anchor's `v` is not
   `"agw-evidence-v2"` or its signature does not verify under the key: problem
   `anchor_invalid`, `intact = false`, and the anchor is discarded. An
   unsigned anchor proves nothing, and comparing against one would let anyone
   able to hand the auditor a line manufacture a "forked history" finding.
   If an anchor remains:
   - if `headSeq < anchor.seq`: problem `rollback`, `intact = false`;
   - else if `anchor.seq` is not in `seen`: problem `missing_anchor`, `intact = false`;
   - else if `seen[anchor.seq] ≠ anchor.hash`: problem `forked`, `intact = false`.
5. If a key was given:
   - `unanchoredRecords = max(0, headSeq − signedThrough)`. A reordered log
     can end on a record numbered below the last verified checkpoint;
     implementations using unsigned arithmetic must not let that wrap;
   - if `checkpoints = 0` and `records > 0`: problem `unanchored`,
     `intact = false`.

### 6.4 Result

A conformant verifier MUST report `intact`, `records`, `checkpoints`,
`headSeq`, and — when a key was given — `signedThrough` and
`unanchoredRecords`. It MUST report every problem with its kind and the
sequence number it concerns, and MUST report them in the order produced by the
algorithm above.

It MUST NOT describe a log with `unanchoredRecords > 0` as verified without
qualification: those are precisely the records that could be removed without
detection.

It MUST NOT describe an intact log with `records = 0` as verified: there is
nothing to verify, and an empty log is also what removing every record
produces. Only an anchor (§6.3) tells the two apart. It reports such a log as
empty; the result is otherwise unchanged (`intact` remains true).

Each problem carries a sequence number: the record's `seq` for `version`,
`superseded_format`, `sequence`, `chain` and `content`; the checkpoint's `seq`
for `checkpoint`; `lastSeq + 1` for `malformed`; `headSeq` for `unanchored`
and `rollback`; the anchor's `seq` for `anchor_invalid`, `missing_anchor` and `forked`.

Problem kinds are normative and stable: `malformed`, `version`,
`superseded_format`, `sequence`, `chain`, `content`, `checkpoint`,
`unanchored`, `anchor_invalid`, `rollback`, `missing_anchor`, `forked`.

## 7. What a verified log proves, and what it does not

**Proves**, given the key and assuming the key was held only by the producer:

- no record up to `signedThrough` was altered, removed, inserted or reordered;
- the log was not rewritten from genesis after any checkpoint it contains;
- with an anchor, the log was not rolled back to before the anchor.

**Does not prove:**

- that anything the producer did not see happened or did not happen. A record
  with `Producer` beginning `observed:` is what the workload *reported*; a
  compromised workload can lie, and the chain faithfully preserves the lie;
- that the records after `signedThrough` are complete;
- that the producer's clock was right. Timestamps are the producer's claim;
- that the key was not stolen. Custody is outside this format. Keep the
  checkpoint key somewhere the producer's own compromise does not reach —
  a separate signing daemon (`--key unix:…`) or a KMS.

## 8. Versioning

The version string selects the hash input. A future incompatible change MUST
use a new version string, and a verifier MUST refuse (problem `version`) a
version it does not implement rather than guess.

## Appendix A. Relationship to the IETF Agent Audit Trail draft

[`draft-sharif-agent-audit-trail-04`](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)
(15 September 2026, individual submission) specifies a hash-chained audit
record for AI agents. It and this format answer overlapping questions with
different designs:

| | this format | AAT-04 |
|---|---|---|
| canonicalisation | length-prefixed fields, fixed order | RFC 8785 JCS |
| what is chained | a fixed set of fields | the whole previous record |
| signatures | periodic checkpoints over the chain head | optional per-record (ES256, ML-DSA-65) |
| field names | Go-style (`AgentID`) | snake_case (`agent_id`) |
| genesis | `prevHash` of 64 zeros | `prev_hash: null`, plus a mandatory `lifecycle`/`session_start` record |
| test vectors | yes, §Status | none published as of -04 |

`agw audit export --format aat` converts a chain to AAT-04 records; the
mapping is in `docs/aat-mapping.md`. The export is **unsigned**: the Ed25519
checkpoint over the source chain is the integrity evidence, and the AAT file
should travel with it.

Two observations about -04 worth raising with its author, both found while
implementing the mapping:

1. **`prev_hash` input is described two ways.** §6.1 directs verifiers to
   remove `signature` and `signature_classical` before recomputing, while §6.3
   step 2 removes only `batch`. The two produce different hashes for any signed
   record. An unsigned export is unaffected, which is one reason ours is
   unsigned until this is settled.
2. **`trust_level` grades the agent's credential, and cannot express identity
   by provenance.** L0 is "no cryptographic identity". An agent confined by
   this system deliberately holds no credential — its identity is the network
   path it arrived on, attested by the supervisor that created it — which is
   stronger assurance than L1 in the threat model of a compromised agent, and
   is recorded as L0. `recording_component` partly compensates, and the export
   always sets it.
