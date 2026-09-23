# Containment demo

An AI agent with **root inside its own sandbox** and `CAP_NET_ADMIN`, actively
trying to escape, cannot reach anything policy does not permit — and every
attempt lands in a chain anyone can verify without us.

```bash
./demo/run.sh
```

Needs Docker and Go. Nothing else. Takes about a minute.

## What it proves

Thirteen assertions, each printed with what was tried and what happened:

| # | The agent tries | Result |
|---|---|---|
| 1 | `169.254.169.254:80` directly — the cloud metadata endpoint | no route |
| 2 | `1.1.1.1`, `140.82.121.4`, `8.8.8.8` directly, ignoring the proxy | no route |
| 3 | `ip route add default` as root, then egress | **route accepted, egress still fails** |
| 4 | read the evidence log from inside the sandbox | not in its namespace |
| 5 | `CONNECT 169.254.169.254:80` through the proxy | `403 metadata_endpoint` |
| 6 | `CONNECT evil.example.com:443` | `403 not_in_allowlist` |
| 7 | `CONNECT 10.0.0.1:22` — internal pivot | `403 private_address_denied` |
| 8 | `CONNECT 127.0.0.1:9090` — the proxy's own control port | `403 loopback_denied` |
| 9 | `GET https://pypi.org/simple/` — the one permitted destination | `200 OK` |
| 10 | hold a tunnel open, then get revoked | closed mid-flight |

Row 3 is the one to look at. The agent **successfully modifies its own routing
table** — and it changes nothing, because the NAT rule that would carry the
traffic lives on the host, in a trust domain the agent has no access to. That
is the difference between confinement and a setting the agent can turn off.

Row 8 matters for a different reason: the kill switch that can revoke this
agent is not reachable from the network the agent is on. It is a unix socket,
not a port.

## Measured

From the last run:

```
kill switch          310µs to close 2 live connections
evidence             43 records, 5 checkpoints, signed through seq 43
verification         VERIFIED — no record altered, removed or reordered
```

The claim is sub-100ms teardown. In-process it is three orders of magnitude
under that, and `internal/confine` asserts the bound in CI rather than
describing it (`TestKillSwitchLatencyIsBounded`).

## How the containment works

```
  ┌──────────────── agw-confined (internal, 172.31.99.0/24) ─────────────┐
  │                                                                      │
  │   agent (172.31.99.20)  ── root, CAP_NET_ADMIN, no default route     │
  │       │                                                              │
  │       └── the only reachable host is the proxy                       │
  │                                                                      │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │
                        proxy (172.31.99.10)
                                  │
  ┌───────────────────────────────┴──────────────────────────────────────┐
  │                agw-egress — has a route out. Proxy only.             │
  └──────────────────────────────────────────────────────────────────────┘
```

The confined network is created `--internal`, so Docker never installs the
host NAT rule that would carry its traffic outward. The agent cannot restore
what was never created on its side of the boundary.

This is the Docker expression of the general property: **the enforcement point
must live in a different trust domain than the workload.** The same design maps
to a Kubernetes sidecar or DaemonSet, and most strongly to a Firecracker
host-side tap device, where enforcement sits outside the guest kernel entirely.

## Verifying the evidence yourself

The demo leaves two files in `demo/.work/evidence/`:

```bash
agw audit verify demo/.work/evidence/evidence.jsonl --key demo/.work/evidence/checkpoint.pub
agw audit show   demo/.work/evidence/evidence.jsonl

# or with the standalone verifier, which shares no code with what wrote the log
agw-verify --key demo/.work/evidence/checkpoint.pub demo/.work/evidence/evidence.jsonl
```

No account, no network, no access to the deployment. That property is what
lets this run in an air-gapped evaluation environment where a SaaS agent
security product structurally cannot.

## A second substrate, where the enforcement is ours

`demo/run.sh` uses a Docker `--internal` network. That is a real deployment,
but the containment is Docker's — an honest reading is "we configured a
runtime", not "we enforce".

`internal/confine/netns` does it directly: namespace, interface pair,
addressing, routing, NAT and firewall, all applied by us. Routing and NAT are
deliberately set up so egress *would* work, and only then is the filter
applied. `TestTheFirewallIsTheControl` flushes our forward chain and nothing
else, and requires that egress starts working — if it did not, containment
would be an accident of missing configuration.

Single command, on Linux as root:

```bash
agw run --policy policy.yaml --evidence ev.jsonl --key ck.key -- python harness.py
```

```
agw: sandbox agw-run  workload agent-eval-01 at 10.77.0.2  proxy 10.77.0.1:18080
  direct 169.254.169.254:80      blocked
  direct 1.1.1.1:443             blocked
  proxy CONNECT 169.254.169.254  403  reason=metadata_endpoint
agw: evidence ev.jsonl (1 records)   VERIFIED
```

## What the workload attempted, not just what it asked us for

Packets the firewall refuses never reach the proxy. Recording only what
arrives at the proxy would mean a workload probing `169.254.169.254` directly
— rather than asking us for it — left no trace at all. That is backwards: a
direct probe is the stronger signal, because the workload chose not to ask.

`agw run` therefore records firewall refusals too, categorized:

```
agw: egress allowed 0, denied 0 (at the proxy)
agw: refused at the firewall: metadata 4, private 4, external 4, host 0

TIME                  SEQ   DECISION                ACTION       AGENT
2026-09-19 06:32:16   1     deny/metadata_endpoint  net.connect  agent-eval-01
2026-09-19 06:32:20   3     deny/private_network    net.connect  agent-eval-01
2026-09-19 06:32:24   5     deny/external           net.connect  agent-eval-01

VERIFIED — no record was altered, removed or reordered
```

Counters rather than packet logging: `/dev/kmsg` is unreadable inside a
container, shared between tenants, and lossy under rate limiting, and
containers are exactly where agents run.

## What this demo does NOT show

Stated plainly, because the [coverage table](../docs/coverage.md) is more use
than a claim of completeness:

- **It does not stop the agent going rogue.** It bounds what a rogue agent can
  reach. The agent in this demo is fully hostile the entire time.
- **It does not prevent sandbox escape** via a kernel or hypervisor bug. That
  is the substrate's job — Firecracker, gVisor, Kata.
- **TLS is not decrypted.** Policy here is destination-level (SNI/host). Per
  action policy needs tier-2 interception, which is a deliberate opt-in.
- **Docker `--internal` is the demo's boundary, not a production recommendation.**
  Production wants a netns the workload has no capability over, or a
  host-side tap.
- **The agent is honest about what it could not test.** A missing tool prints
  `NOT TESTED`, never `contained`.
- **Refusal detail is per category, not per connection.** Firewall-refused
  traffic *is* now in the chain (see below), but as categorized counts —
  "four packets refused toward cloud metadata" — not per-connection records
  with source ports. The category is the finding; the ephemeral port is not.
  Per-packet detail would need an nflog netlink listener.
