# Mapping to the IETF Agent Audit Trail draft

`agw audit export EVIDENCE --key PUB --format aat --out run.aat.jsonl` converts
an evidence chain into records of
[`draft-sharif-agent-audit-trail-04`](https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/)
(15 September 2026, individual submission). This page says what every field is
made from, and where the mapping is a judgement call rather than a
correspondence.

The draft is a moving target. This mapping follows **-04** exactly and says so
in every genesis record (`recording_component: urn:agw:exporter:draft-sharif-agent-audit-trail-04`).

## Guarantees

- **Only verified chains are converted.** The export checks the source
  against its checkpoint signatures first and refuses (exit 2) if it does not
  verify. Converting a tampered chain would produce a fresh, internally
  consistent AAT chain that hides what was altered.
- **The output passes the draft's verifier obligations** (§6.3 steps 1, 2, 4,
  5, 6, 7), mandatory fields and enumerations, checked by `internal/aat.Check`
  before it is written.
- **The output is deterministic.** The same chain always produces the same
  bytes, so two parties can compare exports.
- **Every AAT record points back** to the evidence record it came from
  (`action_detail.agw_seq`, `agw_hash`), so either file can be checked against
  the other.
- **The output is unsigned.** Integrity is carried by the Ed25519 checkpoints
  over the source chain. Keep the two files together. See *Signatures* below.

## Fields

| AAT field | Made from | Notes |
|---|---|---|
| `record_id` | SHA-256 of the evidence record's hash, shaped as UUIDv4 | Deterministic. v4 asks for unpredictable bits; a hash output is. |
| `timestamp` | record `timestamp`, UTC, RFC 3339 | |
| `agent_id` | `urn:agw:agent:<tenant>:<agent>` | Each part percent-escaped, so neither can inject a separator. `unattributed` when the chain has no agent. |
| `agent_version` | `--agent-version`, default `0.0.0` | **Not in the evidence chain.** The draft requires it; `0.0.0` is SemVer for "unknown". |
| `session_id` | derived from the first record's hash | One chain is one session. |
| `action_type` | see below | |
| `action_detail` | see below; `agw_*` members carry the source record | The draft does not say whether extra members are permitted. They are prefixed so they cannot collide with a future field. |
| `outcome` | `deny` → `denied`, `error` → `failure`, otherwise `success` | Shadow-mode `would_deny` is **not** `denied`: nothing was blocked. The verdict is in `action_detail.agw_shadow_verdict`. |
| `trust_level` | see below | |
| `parent_record_id`, `prev_hash` | chain linkage, `hex(SHA-256(JCS(previous)))` | `null` on the genesis record. |
| `record_phase` | enforcement decisions `pre_execution`; closed connections and self-reported activity `post_execution`; workload lifecycle `concurrent` | Every denied decision is `pre_execution`, as §4.2 requires. |
| `recording_component` | `urn:agw:producer:<Producer>` | Present on every record. The draft makes it mandatory when the recorder is not the agent, which for an enforcement point is the point. |
| `deny_reasons` | reason code, see below | Only when `outcome` is `denied`. |
| `latency_ms` | `LatencyMS` | Only when non-zero. |
| `risk_score` | risk class: read 0.1, write 0.4, privileged 0.7, destructive 1.0 | Only when the record carries a risk class. The numbers are an ordering, not a probability. |

### `action_type`

| Evidence | AAT | `action_detail` |
|---|---|---|
| `confine.workload.*` | `lifecycle` | `event: workload_registered` / `workload_revoked` |
| `Producer` = `observed:recorder` | `tool_call` | `tool_name`; `parameters_hash` is SHA-256 over the action and resource, because the chain stores no parameters |
| every enforced record | `decision` | `decision_type`: `egress_authorization`, `tool_authorization` or `request_authorization`; `policy_ref` from `RouteID` |
| (synthesised) | `lifecycle` | genesis, `event: session_start`, because the draft requires one and the chain has none |

### `trust_level`

The draft's L0–L4 grade the agent's own credential. That scale cannot express
this system's strongest mode: a confined agent deliberately holds **no**
credential, and its identity is the network path it arrived on, attested by
the supervisor that launched it.

| Evidence | AAT |
|---|---|
| gateway, federated call | `L3` — both organisations' keys verified under a trust grant |
| gateway, registered key | `L2` — a key issued through the control plane |
| everything else, including confinement | `L0` |

Confinement records at `L0` understate them. `recording_component` is what
tells a reader the record was written by an enforcement point the agent could
not bypass.

### `deny_reasons`

The draft's registered codes are used where the meaning genuinely matches:

| Reason code | AAT |
|---|---|
| `workload_revoked`, `credential_revoked` | `AGENT_REVOKED` |
| `replay_detected` | `REPLAY_DETECTED` |
| `request_expired`, `request_not_yet_valid` | `TIMESTAMP_STALE` |
| `policy_denied`, `no_policy_for_agent`, `not_in_allowlist`, `outside_trust_grant` | `CAPABILITY_NOT_GRANTED` |
| `route_unknown` | `ACTION_UNKNOWN` |
| anything else | `AGW_` + the reason code in upper case, e.g. `AGW_METADATA_ENDPOINT` |

## Signatures

The export does not sign records, for two reasons.

1. The draft signs with ES256 or ML-DSA-65. Our checkpoint keys are Ed25519,
   so signing would mean a second key with its own custody, and a signature
   made at export time attests the *export*, not the events.
2. -04 describes the `prev_hash` input for a signed record two ways: §6.1
   removes `signature` and `signature_classical` before hashing, §6.3 step 2
   removes only `batch`. For an unsigned record the two agree.

The source chain's checkpoints remain the integrity evidence. An auditor
verifies the source with `agw audit verify` (or `agw-verify`, which shares no
code with the exporter), then uses the AAT file with AAT tooling, checking any
record against the source through `agw_hash`.

## What would make this a native implementation rather than a conversion

Emitting AAT directly from each enforcement point, with per-record signatures
under a key in separate custody. That is worth doing once -04's `prev_hash`
ambiguity is settled and the draft stabilises; until then a deterministic,
verified conversion keeps the evidence format stable while staying compatible.
