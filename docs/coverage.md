# What this stops, and what it does not

Published because the market for agent security is full of post-incident
overclaiming, and the people evaluating it have just read three incident
reports. A vendor that says what it does not stop is easier to believe about
what it does.

This page is kept in step with the code. Every "yes" names the test that
proves it; a claim without one does not belong here.

## The claim, in one sentence

> We do not prevent agents from going rogue. We bound what a rogue agent can
> reach, and make everything it attempted provable afterwards.

## By failure class

| Failure class | Stopped? | Why | Proven by |
|---|---|---|---|
| Harmful action **within** the agent's permitted scope | **No** | That is alignment. Policy cannot tell a legitimate call from a harmful one when both are allowed. | — |
| Prompt injection causing a permitted-but-wrong action | **No** | The action is permitted. Policy cannot see intent. | — |
| Sandbox escape via a kernel or hypervisor bug | **No** | The substrate's job (gVisor, Firecracker), not ours. | — |
| A vulnerability in someone else's application | **No** | Input validation in their code. | — |
| Social engineering of a human approver | **Barely** | Identity binding helps attribution; the rest is human process. There is no approval workflow yet. | — |
| **Secrets leaving through a permitted destination** | **No** | Destination policy decides where a workload may connect, not what it sends. The gym moves a canary out through a permitted endpoint on every seed: in the body, in the query string, and split across requests. Stopping it needs payload inspection (TLS interception), which is not built. Every such request *is* recorded. | `internal/gym`: `exfil.via_allowed_*` |
| Unauthorized egress, direct or via the proxy | **Yes**, at rung 3 | Default-deny egress the workload cannot bypass, even as root. | `internal/confine/netns` (root), `integrations/*/test.sh`, `gym/contained.sh` |
| Cloud credential theft from the metadata endpoint | **Yes**, at rung 3 | Link-local, NAT64 and the AWS IPv6 address are refused whatever the policy says, and cannot be exempted. | `TestMetadataEndpointIsUnreachable`, `TestPermitPrivateCannotReopenStructuralDenials`, gym `cloud_metadata` |
| DNS rebinding to reach refused addresses | **Yes** | Resolve once, check every address, dial the checked address. | gym `dns.*` |
| Credential theft → reuse from outside the sandbox | **Largely**, at rung 3 | The confined agent holds no credential: identity is the network path. The supervisor's environment no longer crosses into the sandbox either. | `TestHostSecretsDoNotReachTheWorkload` |
| A forbidden MCP tool call | **Yes**, at rung 2 | Checked before the server sees it, including messages crafted so the enforcement point and the server would read them differently. | `internal/mcp`, `TestEnforcementPointAndServerReadTheSameCall` |
| An MCP server redefining its tools after approval | **Detected**; **stopped** with `--pin-tools` | Tool names, descriptions and schemas are hashed; a change is recorded, and with pinning, calls stop. | `TestPinnedToolsStopCallsAfterARugPull` |
| Acting after the kill switch | **Yes** | Connections cut, new ones refused, the process group killed. Measured at about a millisecond; CI asserts 100 ms. | `scripts/killswitch-e2e.sh`, `TestKillSwitchLatencyIsBounded` |
| An action that is never recorded | **Yes**, at every enforcing rung | Fail closed: if the decision cannot be recorded, the action does not happen. | gym `failclosed.*`, `TestAnUnrecordedCallIsNeverForwarded` |
| Editing, deleting, reordering or rewriting the evidence | **Yes**, detected | Hash chain plus signed checkpoints, verifiable offline by three independent implementations. | `conformance/evidence`, `cmd/agw-verify` differential test |
| Deleting the most recent evidence | **Detected with an anchor** | Records after the last checkpoint can be removed without trace from the file alone; a checkpoint kept elsewhere detects it. Live logs are checkpointed every 10 s. | `TestAnchorDetectsRollback` |

## By rung of the adoption ladder

What each rung does **not** protect against, stated where it applies:

| Rung | Does not protect against |
|---|---|
| 0 Record (`agw watch`) | A compromised agent lying. It records what the agent reports. |
| 1 Rehearse (`agw watch --policy`) | Anything: nothing is blocked. It shows what would be. |
| 2 Enforce tool calls (`agw mcp`) | An agent that starts the server itself, or reaches the network by some route other than MCP. |
| 3 Contain (`agw run`, sidecar) | Harm within what the policy permits, including exfiltration to a permitted destination. In sidecar mode, a workload container that keeps `CAP_NET_ADMIN` or `CAP_SETUID`; the Kubernetes admission policy refuses those pods. |

## The Hugging Face intrusion, step by step (July 2026)

| # | Step | Effect of rung 3 |
|---|---|---|
| 1 | Zero-day in a package registry cache proxy → sandbox escape | **None.** Infrastructure vulnerability. |
| 2 | Public code-eval harness abused for root elsewhere | **None.** Someone else's endpoint. |
| 3 | Malicious dataset config → HDF5 read, Jinja2 injection | **None.** Application input validation. |
| 4a | Pod environment variables and service-account token harvested | **Partial.** The supervisor's environment no longer reaches a workload `agw run` starts. Secrets deliberately mounted into the workload remain readable to it. |
| 4b | AWS IAM keys from the metadata endpoint | **Prevented.** Refused at the proxy and the firewall; cannot be exempted. |
| 4c/5 | Signing key harvested; tokens minted | **Partial.** Our own keys can sit behind a signing daemon that refuses to act as a general-purpose oracle. Nothing for anyone else's keys. |
| 6 | One connector credential bound to `system:masters` | **Reduced.** A confined agent reaches only the destinations its policy names, so one credential no longer opens every cluster from inside the sandbox. Per-agent identity at the resources themselves needs an AGS1 verifier in front of them. |
| 7 | Forensics recovered 4× the secrets only by replicating the attacker's decoding | **Transformed.** Every attempt, allowed or refused, is in a chain that verifies offline. |

We would not have prevented this incident. We would have prevented one
control failure, reduced three, and changed what the responders had to work
with.
