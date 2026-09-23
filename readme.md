# agw — confine AI agents, and prove what they did

A containment layer you run AI agents inside. It enforces what they can reach,
refuses what they may not do, and keeps a record of everything they did **and
attempted** that anyone can verify with a file and a public key: no account,
no network, no trust in us.

> We do not prevent agents from going rogue. We bound what a rogue agent can
> reach, and make everything it attempted provable afterwards.

Three verbs, and every feature serves one of them:

- **Confine**: the agent reaches only what policy allows. It cannot opt out,
  because the enforcement point is outside its trust domain, and that holds
  when it has root.
- **Decide**: every action is checked before it happens, against policy, with
  a stable reason code when refused.
- **Prove**: every allow and every refusal lands in a hash-chained, signed
  evidence log ([RFC-0009](docs/rfcs/RFC-0009-evidence-chain-format.md)),
  checkable offline by three independent verifiers, one of which runs in your browser.

What it does **not** stop is on [one page](docs/coverage.md), including the
result our own adversarial testing keeps producing.

**Website: <https://aryan22g.github.io/agw/>**. It includes a
verifier that checks evidence in your browser, with nothing uploaded.

---

## Install

```bash
# Linux and macOS: checks the download's checksum, then installs agw,
# agw-verify, ags and ags-signd
curl -fsSL https://aryan22g.github.io/agw/install.sh | sh

# the container image
docker run --rm ghcr.io/aryan22g/agw version

# from source (Go 1.26+)
go install github.com/Aryan22g/agw/cmd/agw@latest
go install github.com/Aryan22g/agw/cmd/agw-verify@latest

# from a clone
make build            # everything into ./bin
make dist             # release archives for five platforms, with SHA256SUMS
make image-agw        # the container image
```

Tagging `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes the
archives, checksums and a multi-architecture image to
`ghcr.io/aryan22g/agw`, each with a build-provenance attestation.

`agw-verify` is the standalone verifier: one file, standard library only,
opens no sockets. Give it to your auditor.

## Five minutes

```bash
agw init                 # a signing key in ~/.agw, a starter policy, and what to run next
agw watch                # prints three OTEL_* variables; set them where your agent runs
```

Any OpenTelemetry exporter works on its defaults: HTTP/protobuf, HTTP/JSON or
gRPC. From then on you have signed evidence of what your agents do:

```bash
agw audit verify agw-evidence-*.jsonl --key ~/.agw/checkpoint.key.pub
agw tail agw-evidence-*.jsonl
```

## The ladder

Each rung works on its own, and you can stop at any of them. Each is one step
further than the last, and each rehearses before it enforces.

| Rung | Command | What you get | What it does not do |
|---|---|---|---|
| 0 Record | `agw watch` | Signed evidence from the telemetry agents already emit | Stop a compromised agent from lying about itself |
| 1 Rehearse | `agw watch --policy p.yaml` | What policy **would** refuse (`agw audit show --would-deny`); a drafted policy (`agw policy suggest`) | Block anything |
| 2 Enforce tool calls | `agw mcp --policy a.yaml --agent A -- npx some-mcp-server` | Forbidden MCP tool calls refused before the server sees them | Stop an agent that reaches the network some other way |
| 3 Contain | `sudo agw run --policy p.yaml -- python agent.py` | Default-deny egress the agent cannot bypass even as root; the cloud metadata endpoint refused whatever policy says; the kill switch (`agw suspend`) cuts it off in about a millisecond | Stop harm within what the policy permits |

Kubernetes, Docker Compose, GitHub Actions, MCP clients (Claude Desktop,
Cursor, Claude Code, VS Code) and OpenTelemetry pipelines:
**[docs/integrations.md](docs/integrations.md)**, each marked with how it was
verified.

## Checking evidence

```bash
agw audit verify EVIDENCE.jsonl --key checkpoint.pub            # exit 0 intact, 2 not
agw audit verify EVIDENCE.jsonl --key checkpoint.pub --anchor KEPT   # also detects deleted recent records
agw audit export EVIDENCE.jsonl --key checkpoint.pub --out q3.bundle.json
agw audit export EVIDENCE.jsonl --key checkpoint.pub --format aat    # IETF agent-audit-trail-04
```

Records after the last checkpoint can be deleted without trace from the file
alone. To catch that, keep a checkpoint somewhere the log's owner cannot
change, and pass it as the anchor next time:

```bash
grep '"type":"checkpoint"' EVIDENCE.jsonl | tail -1 > kept.json   # store this elsewhere
agw audit verify EVIDENCE.jsonl --key checkpoint.pub --anchor kept.json
```

The format is specified in [RFC-0009](docs/rfcs/RFC-0009-evidence-chain-format.md),
with a [conformance corpus](conformance/README.md) so anyone can build a
verifier and check it. Mapping to the EU AI Act's record-keeping articles:
[docs/compliance/eu-ai-act-article-12.md](docs/compliance/eu-ai-act-article-12.md).

## How it is tested

Unit tests are not enough for a security product, so four more layers sit on
top of them. CI runs all of them on every change.

| Layer | What it proves |
|---|---|
| `go test -race ./...` **as root on Linux** | The containment tests build real network namespaces and nftables rules, and prove an agent with root cannot reach the metadata endpoint or remove the firewall. CI fails if they skip. |
| [The gym](gym/README.md) | A generated enterprise world with a hostile agent in it, scored against **the world's own receipt log** rather than the product's account of itself. Egress with no evidence record is the one failure a product cannot self-report. |
| Three independent verifiers | `agw-verify` (standard-library Go) and the site's JavaScript verifier are written from the spec alone and run against the reference on thousands of mutated logs. That search found an attack where a verified log displayed a decision other than the one signed, and several places the spec was ambiguous. |
| Integration tests against the real thing | The official MCP client and server; Python and Node OpenTelemetry SDKs; the OpenTelemetry Collector; a Kubernetes cluster with a root attacker; Docker Compose; the kill switch with its latency asserted. |

## Documentation

| | |
|---|---|
| [Integrations](docs/integrations.md) | Every environment, with copy-paste configuration |
| [Coverage](docs/coverage.md) | What this stops and what it does not |
| [RFC-0009](docs/rfcs/RFC-0009-evidence-chain-format.md) | The evidence format, implementable without this code |
| [AAT mapping](docs/aat-mapping.md) | Conversion to the IETF agent-audit-trail draft |
| [EU AI Act](docs/compliance/eu-ai-act-article-12.md) | Articles 12, 19, 26(6) |
| [The gym](gym/README.md) | The adversarial environment |
| [RFC-0002](docs/rfcs/RFC-0002-ags1-request-signing-profile.md) | AGS1, the request-signing profile |
| [Security](SECURITY.md) | Reporting a vulnerability |

---

# Signed requests: AGS1

Everything above is about agents you should not trust. AGS1 is for the other
case: agents that are yours, calling APIs you protect, where the question is
*which agent sent this request*. An agent signs each HTTP request with its own
Ed25519 key, and the receiving service verifies it before acting.

AGS1 is a profile of RFC 9421 HTTP Message Signatures, specified in
[RFC-0002](docs/rfcs/RFC-0002-ags1-request-signing-profile.md). `pkg/ags1` is
the frozen v1 implementation, used by the SDKs and by `httpmsig.Verify` on the
receiving side.

- Ed25519 over RFC 9421 HTTP Message Signatures
- 11 covered components for a body-bearing request, 9 for a body-less one --
  both closed sets, so a signer cannot shrink what its signature covers
- `kid` is the RFC 7638 JWK thumbprint (conformance vector: RFC 8037 A.3)
- `alg` is forbidden on the wire; the algorithm comes from the credential
- JSON bodies are canonicalized with RFC 8785 JCS before digesting
- 300s age window, 60s future skew, nonce reserved once per credential

Changing any normative value is wire-breaking and requires a new profile
version and `tag` -- never an edit in place.

## SDKs

### Python

```bash
pip install "git+https://github.com/Aryan22g/agw#subdirectory=sdks/python"
```

```python
from ags_sdk import Client, load_keystore

rec = load_keystore()          # ~/.ags/credentials.json, written by `ags keygen`
client = Client(
    gateway_url="https://api.example.com",
    tenant_id=rec["tenantId"],
    agent_id=rec["agentId"],
    private_key=rec["_private_key"],
    key_id=rec["keyId"],
)
response = client.post_json("/v1/tools/github/repos/acme/app/issues",
                            {"title": "Filed by an agent"})
```

### Go

```bash
go get github.com/Aryan22g/agw/sdks/go/agentgw@latest
```

```go
client, err := agentgw.New(agentgw.Config{
    GatewayURL: "https://api.example.com",
    TenantID:   "tenant-alpha",
    AgentID:    "agent-support",
    PrivateKey: priv,
})
resp, err := client.PostJSON(ctx, "/v1/tools/github/repos/acme/app/issues",
    map[string]any{"title": "Filed by an agent"})
```

Signing is a `RoundTripper`, so `client.HTTPClient()` can be handed to any
library that accepts an `*http.Client`. The Python SDK is an independent
implementation, byte-identical to Go on every conformance vector.

## The `ags` CLI

```bash
ags keygen      # an Ed25519 key, its AGS1 key id, and the public JWK to hand to a verifier
ags sign        # sign a request and print the signature base (debugging)
ags verify      # verify a signed request (the conformance entry point)
ags thumbprint  # derive an AGS1 key id from a public key
ags doctor      # diagnose a local setup: key id, reachability, clock skew
```

`ags doctor` exists because a verifier should not explain why a signature
failed -- doing so would make it an oracle for which keys exist. The diagnosis
happens locally, where the private key is.

## Key custody: `ags-signd`

A process that signs does not have to hold its key. `ags-signd` (installed
with the others, and in the image) holds it in a
separate process and signs on request; the caller never sees the key material,
and the protocol has no operation that would return it.

It is not a general-purpose signing oracle. It works out what each message is
for from the message's own bytes, signs only the canonical forms of the
purposes it was started with, rate limits each purpose, and counts refusals.
A daemon started for evidence checkpoints cannot be used to sign anything
else:

```bash
ags-signd -socket /run/agw/sign.sock -key /etc/agw/checkpoint.key --purposes evidence-checkpoint
agw proxy ... --key unix:/run/agw/sign.sock
```

A KMS or PKCS#11 HSM implements the same `signer.Signer` interface, so moving
to one is a backend change, not a redesign.

---

## Conformance

Two corpora, each with hand-written expectations and negative cases, so an
implementation in any language can be checked without this code:

- **Evidence:** [conformance/evidence](conformance/README.md), 39 vectors for
  RFC-0009. Three verifiers pass it, and CI searches thousands of mutated logs
  for any disagreement between them.
- **AGS1:** `pkg/ags1/vectors/ags1-v1.json`, 7 positive and 5 negative vectors
  pinning the canonical body, content digest, signature input, signature base
  and signature for concrete requests.

```bash
make conformance                            # evidence: all three verifiers + the differential search
go test ./pkg/ags1/vectors/                 # AGS1: this implementation
python3 sdks/python/tests/test_conformance.py   # AGS1: the Python SDK
./bin/ags verify -url ... -signature ...    # AGS1: another implementation
```

The AGS1 corpus is generated from `pkg/ags1` and is a regression guard on the
wire format: a one-byte change to a signature base fails the suite, which is
the signal you want, because that byte would silently invalidate every
deployed SDK. Regenerate only on a deliberate profile version change:

```bash
go run ./pkg/ags1/vectors/gen -out pkg/ags1/vectors/ags1-v1.json
```

---

## Repository layout

```
cmd/agw             the containment plane: init, watch, mcp, run, proxy, sidecar-init, suspend, audit, policy
cmd/agw-verify      standalone evidence verifier (standard library only)
cmd/agw-gym         the adversarial environment
cmd/ags             AGS1 developer CLI (keygen, sign, verify, thumbprint, doctor, audit)
cmd/ags-signd       key custody: signs without handing out the key

pkg/ags1            FROZEN AGS1 v1 wire profile, shared by every SDK
sdks/go/agentgw     Go SDK
sdks/python         Python SDK (independent implementation of AGS1)

internal/confine         egress policy, structural guard, proxy, netns sandbox, sidecar
internal/mcp             MCP enforcement (HTTP and stdio)
internal/recorder        OpenTelemetry ingest (HTTP/JSON, HTTP/protobuf, gRPC)
internal/gateway/audit   the evidence chain: writer, reference verifier, checkpoints
internal/gateway/authz   tool-call policy (used by agw mcp)
internal/aat             IETF agent-audit-trail export
internal/strictjson      refusing JSON two parsers would read differently
internal/gym             the adversarial environment

conformance/        test vectors for the evidence format
integrations/       Kubernetes, Docker Compose, GitHub Actions
site/               the website, including the in-browser verifier
docs/rfcs           normative specifications
```

---

## Known gaps

The honest list is [docs/coverage.md](docs/coverage.md). A few that are about
the software rather than the threat:

- **TypeScript and Rust AGS1 SDKs are not started.** The conformance corpus
  and `ags verify` exist so they can be built against a fixed target.
- **No KMS or HSM backend yet.** `ags-signd` is the shape one will take.
- **Evidence is written to local disk.** It is durable and fsynced; retention
  is left to the storage you put it on.

## Operational notes

**Evidence failure fails closed.** If the evidence record for an allowed
action cannot be written, the action is refused rather than performed -- an
action that cannot be proven afterwards does not happen.

## License

[Apache License 2.0](LICENSE). Verification must never require us, so
everything needed to produce and check evidence (the CLI, the verifiers, the
specification, the SDKs) is open source and stays that way.
