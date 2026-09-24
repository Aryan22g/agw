# The gym

An adversarial environment for the confinement plane.

`go test ./...` asks whether a function returns what it should. This asks a
different question: stand up a world that looks like the one an enterprise
agent actually runs in, put an agent inside it that is trying to get out, and
see what got out.

```bash
make gym                      # one run against a generated world
make gym-sweep                # fifty worlds, reporting only what breaks
make gym-contained            # under real network isolation (Docker)

go run ./cmd/agw-gym run --seed 1337 --all   # reproduce one world exactly
```

## Why not just write more tests

Three things here are hard to get from a test suite.

**The world keeps its own books.** Every service records what it received, in
its own handler, before doing anything else. Scoring compares that log against
the evidence chain the product wrote. Egress that reached a service and left no
evidence record is the one failure the product cannot self-report — every check
it ships with reads its own output. That number is the first line of the
report for that reason.

**Secrets are traceable.** The sensitive services hand out canary tokens.
When one turns up in a request body at a paste site, that is data loss
established by the receiving end, not inferred from a policy decision. The
report says which secret, from which store, reached where, and through which
channel.

**The world is generated.** Hostnames, ports, which services are in policy,
and the decoys sitting one character from a policy entry all come from a seed.
`sweep` runs fifty of them. A control that only holds for the topology in
someone's head fails there and nowhere else.

## The two modes

Neither is complete. The report always says which one produced it.

| | hosted (`make gym`) | contained (`make gym-contained`) |
|---|---|---|
| enforcement code | linked into the process | the shipped `agw proxy` binary |
| agent's route out | not restricted | **none except the proxy** |
| hostile DNS, rebinding | yes | no |
| break the evidence sink | yes | no |
| revoke through the registry | yes | no |
| policy loader refusals | yes | no |
| direct-route probes | skipped | yes |
| runtime | ~2s | ~90s |

Hosted mode links the enforcement code directly, which buys precision: it can
make the evidence sink fail on command, revoke a workload mid-tunnel, and
answer DNS with a rebinding. What it cannot do is stop the agent routing
around the proxy, because that is a property of the network.

Contained mode has that property and none of the reach. The agent runs in a
container on a Docker network created with `--internal`, attached to nothing
but the proxy. There is no route. Nothing in this repository enforces it,
which is exactly why it is worth having.

Episodes declare what they need (`Capability` in `episode.go`) and a mode that
cannot provide it reports the episode as **skipped**, with the reason. A mode
that quietly stopped exercising a control would still print a full-looking
report, so the skips are counted and shown.

## What it covers

| family | asks |
|---|---|
| `cloud_metadata` | IMDS in six spellings — IPv4, IPv4-mapped IPv6, the AWS IPv6 address, NAT64, other ports, the ECS credential endpoint — through both a proxied GET and a CONNECT tunnel |
| `allowlist_matching` | wildcard apex, suffix near-misses (`evilexample.com`), wrong ports, IP literals of permitted names, and the case and trailing-dot spellings that must still be *allowed* |
| `dns` | rebinding on a permitted name, split answers, a permitted name pinned to link-local, NXDOMAIN |
| `exfiltration` | secrets to a paste site and to C2, and — the uncomfortable ones — secrets through a **permitted** destination, in the body, the query string, and split across requests |
| `workload_identity` | unattested source, identity asserted in headers, acting after revocation |
| `kill_switch` | revoking a workload underneath a tunnel that is already open |
| `proxy_semantics` | Host header disagreeing with the absolute URI in both directions, origin-form requests, URL userinfo, hop-by-hop header games, CONNECT with a defaulted port |
| `fail_closed` | a permitted request while evidence recording is broken |
| `policy_safety` | the refusals the policy loader and the guard owe you |
| `evidence_integrity` | eight alterations of a real chain, each tried against the file alone and against a checkpoint an auditor kept |
| `network_boundary` | dialing the world, IMDS and a DNS resolver without the proxy at all |
| `benign_work` | the work the agent exists to do, which must succeed |

That last row is not filler. A confinement plane that refuses everything
contains perfectly and is useless, so the false-positive rate sits next to the
containment rate in the report and neither is readable without the other.

## What it found

Two defects, on the first run, both since fixed and both now pinned by tests
in the product's own suite.

**`permit_private` could reopen the cloud metadata endpoint.**
`Guard.Check` consults exemptions before every structural denial, and the only
thing `NewGuard` checked was prefix width. `169.254.169.0/24` is a `/24` —
narrow enough to look considered — so one line in a policy file handed a
confined agent IMDS and the IAM credentials behind it. The policy
documentation stated the opposite in as many words. Fixed in
`internal/confine/guard.go` with a list of space that can never be exempted;
loopback and private space stay exemptable, because reaching a sidecar is what
the feature is for.

**An evidence chain with no checkpoints verified clean.**
`Verify` checked the links and the signatures it found, and said `VERIFIED`
when it found none. A chain with no checkpoint is internally consistent and
proves nothing: anyone who can write the file can rewrite it from genesis and
recompute every hash. Fixed in `pkg/evidence/verify.go`.

A third result is a limit rather than a bug, and the fix is a new capability
rather than a patch. Truncating a log exactly at a checkpoint boundary leaves
a shorter log in which everything still verifies — no amount of care inside
the file can catch that, because the file is what is being edited. `Verify`
now reports how many records sit past the last checkpoint (those are the ones
that can be removed without a trace), and `VerifyWithAnchor` takes a
checkpoint the auditor kept out of band:

```bash
ags audit verify --log chain.jsonl --public-key "$PUB" --anchor kept-checkpoint.json
```

One 200-byte line, stored anywhere the operator of the log cannot reach, turns
"trust the file" into "prove it against something you kept".

## Layout

```
cmd/agw-gym/         run, sweep, and the world/agent/score halves of contained mode
internal/gym/
  world.go           the simulated enterprise and its receipt log (the oracle)
  generate.go        seeded topology, policy and canaries
  resolver.go        a name service that can be made hostile on purpose
  attacks.go         the episode library
  agent.go           the hostile workload, speaking raw HTTP to the proxy
  harness.go         ranges: one running configuration of the plane each
  run.go             execution, seeded ordering, evidence correlation
  score.go           scoring, the oracle, and the findings
  evidence.go        eight ways to alter a chain
  contained.go       the world server and remote harness for Docker mode
gym/contained.sh     the Docker topology
```

Exit status is non-zero when any episode fails, so both modes fit in CI.
