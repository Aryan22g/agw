# EU AI Act: record-keeping (Article 12) and log retention (Articles 19 and 26)

How the evidence this software produces maps to the record-keeping
obligations of Regulation (EU) 2024/1689, and where it does not reach.

**This is an engineering mapping, not legal advice.** Whether a system is
high-risk, which obligations apply, and from which date, depend on the system
and on the Regulation as amended. Application dates have been the subject of
the Digital Omnibus proposal; confirm the dates that apply to you with counsel.

## Article 12

### 12(1): automatic recording of events over the lifetime of the system

> High-risk AI systems shall technically allow for the automatic recording of
> events (logs) over the lifetime of the system.

| What the Article needs | What provides it |
|---|---|
| Recording that is automatic, not discretionary | Every enforcement point writes its decision **before** the action proceeds, and refuses the action if the record cannot be written (fail-closed). The agent cannot choose not to be logged. |
| Over the lifetime of the system | The chain resumes across restarts rather than starting a new one, so a restart does not leave a seam that looks like tampering. Checkpoints anchor it at least every 10 seconds while there is activity. |
| Logs that can be relied on | Hash-linked records with signed checkpoints ([RFC-0009](../rfcs/RFC-0009-evidence-chain-format.md)), verifiable offline with a file and a public key, by a standalone verifier that shares no code with the writer. |

**Where the recording happens matters.** A log an agent writes about itself
(rung 0, `agw watch`) records what the agent *reports*. A log written at an
enforcement point the agent cannot bypass (rung 3, `agw run` or the sidecar)
records what it *did and attempted*. Records carry a `Producer` field that
says which, so an auditor never has to guess.

### 12(2): events relevant to risk, post-market monitoring and operation

> …logging capabilities shall enable the recording of events relevant for:
> (a) identifying situations that may result in the high-risk AI system
> presenting a risk within the meaning of Article 79(1) or in a substantial
> modification; (b) facilitating the post-market monitoring referred to in
> Article 72; and (c) monitoring the operation of high-risk AI systems
> referred to in Article 26(5).

| Point | Relevant events recorded | Fields |
|---|---|---|
| (a) risk situations | Refused actions, with a stable reason code: attempts to reach the cloud metadata endpoint, unlisted destinations, forbidden tool calls, actions after revocation, an MCP server redefining its tools. Refusals are the events that indicate a system operating outside its intended purpose. | `Decision`, `ReasonCode`, `Action`, `ResourceID`, `Risk` |
| (a) substantial modification | A change in the tools an MCP server advertises is recorded with the before and after digests. | `mcp.tools.changed` events |
| (b) post-market monitoring | Every decision, allowed or refused, per agent and tenant, exportable for a period as a self-verifying bundle (`agw audit export --from … --to …`). | `TenantID`, `AgentID`, timestamps |
| (c) monitoring operation by the deployer | Live: `agw tail`, `agw status`. After the fact: `agw audit show` filtered by agent, decision, reason or time. | — |

Which situations present a risk "within the meaning of Article 79(1)" is a
judgement about the system and its purpose. The software records the events;
deciding which ones matter is the provider's and deployer's work.

### 12(3): minimum logging for remote biometric identification (Annex III point 1(a))

Only for that category of system. It requires the period of each use, the
reference database, the input data that led to a match, and the natural
persons who verified the results.

| Requirement | Coverage |
|---|---|
| (a) period of each use | Partly: each action is timestamped, and a session's first and last records bound it. There is no explicit session-start/end event outside the AAT export. |
| (b) reference database checked | Only if the system's own call to that database passes through an enforcement point, where it is recorded as the resource. |
| (c) input data that led to a match | **Not covered.** Payloads are not recorded, deliberately: hashing without retention is planned, storing is not. |
| (d) natural persons verifying results (Art. 14(5)) | **Not covered.** There is no human-approval workflow yet. |

A remote biometric identification system cannot rely on this software alone
for 12(3).

## Retention: Articles 19(1) and 26(6)

Providers (Article 19(1)) and deployers (Article 26(6)) must keep
automatically generated logs under their control for a period appropriate to
the intended purpose, of **at least six months**, unless other law provides
otherwise.

The software produces files; it does not yet retain them. What that means in
practice:

- Evidence files are append-only JSON Lines, one per enforcement point, small
  enough to archive cheaply. Put them on storage with a retention lock
  (object storage with object lock, WORM volumes).
- Keep the checkpoint public key, and a checkpoint line from each period, in
  a **different** place from the evidence. Those let a later reader detect a
  file that was truncated or replaced, including one truncated exactly at a
  checkpoint (`agw audit verify --anchor`).
- Records do not contain request or tool-call payloads, which keeps
  retention from becoming a store of personal data. Resource identifiers such
  as URLs and file paths are recorded and may themselves be personal data;
  assess them.

## Multi-agent chains: Recitals 99 and 100

When several agents, possibly from different organizations, act in a chain
performing a high-risk function, each link needs to be attributable. The
evidence format has fields for the issuing organization, whether a call was
federated, and the trust grant that permitted it, so a producer handling
cross-organization calls can record them. Those fields are hash-protected in the current format, `agw-evidence-v2`. They were **not** in
the superseded v1, and a verifier says so when it meets a v1 record.

## For an auditor

Everything needed to check the evidence independently:

1. The evidence file, and the checkpoint public key obtained from the
   operator through a channel other than the file.
2. `agw-verify --key checkpoint.pub evidence.jsonl`. It is a single
   dependency-free program, and its source is short enough to read before
   running it.
3. Optionally, a checkpoint kept from an earlier period: `--anchor`.
4. For tooling that speaks the IETF agent-audit-trail draft,
   `agw audit export --format aat`, which converts only after verifying.
