# Integrations

Every integration below is marked with how it was verified. **Tested** means
the exact configuration on this page was run against the real third-party
component; **CI** means a job in `.github/workflows/ci.yml` runs it on every
change.

| Where your agent runs | Rung | Integration | Verified |
|---|---|---|---|
| Anything that emits OpenTelemetry | 0–1 Record / rehearse | [`agw watch`](#opentelemetry) | Tested: Python SDK 1.41 (http/protobuf, gRPC), Node SDK (http/protobuf, http/json), Collector 0.161 · CI |
| Any MCP client with a local (stdio) server | 2 Enforce tool calls | [`agw mcp -- CMD`](#mcp) | Tested: official MCP TypeScript SDK client + `@modelcontextprotocol/server-filesystem` · CI (unit) |
| An MCP server over HTTP | 2 | [`agw mcp --upstream`](#mcp) | CI |
| A Linux host or VM | 3 Contain | [`agw run`](#linux-host-agw-run) | Tested as root on Linux · CI (root) |
| Docker / Docker Compose | 3 | [sidecar](#docker-compose) | Tested adversarially · CI |
| Kubernetes | 3 | [sidecar + admission policy](#kubernetes) | Tested on Kubernetes 1.33 (kind) · CI |
| GitHub Actions | 3 | [`integrations/github-action`](#github-actions) | Step scripts run in a Linux container · CI |
| Anything else | – | [the evidence format](#anything-else) | 39 conformance vectors, three independent verifiers |

Start with `agw init`. It creates the signing key and a starter policy, and
prints the next command for each rung.

---

## OpenTelemetry

Point any OpenTelemetry exporter at `agw watch`. No SDK, no code change.

```bash
agw watch --policy agw-policy.yaml      # --policy is optional: rehearsal mode
```

It prints the three variables to set, including a generated bearer token:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf      # or http/json, or grpc on :4317
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <token>"
```

All three OTLP transports are accepted, gzipped or not, so an exporter left on
its defaults works. JSON and protobuf exports of the same spans produce
identical records; a test pins that.

**Frameworks.** Anything that emits OpenTelemetry spans works the same way,
with nothing agw-specific. That includes the OpenAI Agents SDK through its
OTel processors, LangChain and LangGraph through OpenLLMetry or OpenInference,
Pydantic AI and the Vercel AI SDK, which emit OTel natively, and LlamaIndex
and CrewAI through their instrumentations. `agw` reads the GenAI semantic
conventions (`gen_ai.tool.name`, `gen_ai.operation.name`) and the HTTP ones
(`http.request.method`, `url.full`, `server.address`). Only the stock SDKs and
the Collector listed above have been run end to end here.

**Through a Collector.** If spans already go to an OpenTelemetry Collector,
add an exporter rather than changing the agents:

```yaml
exporters:
  otlp_http/agw:                       # "otlphttp" before Collector 0.16x
    endpoint: http://agw-host:4318
    headers:
      Authorization: "Bearer <token>"
service:
  pipelines:
    traces:
      exporters: [otlp_http/agw, your_existing_exporter]
```

`agw watch` binds to `127.0.0.1` by default. To receive from another host,
pass `--listen 0.0.0.0:4318` and keep the token: a recorder anyone can reach
is a place to inject evidence.

**What this rung does not do:** it records what the agent *reports*. A
compromised agent can lie, and the chain faithfully preserves the lie. Records
from this path carry `Producer: observed:recorder` so nobody mistakes them for
enforcement.

---

## MCP

`agw mcp` sits between an MCP client and a server and refuses tool calls the
policy does not allow. Refusals are JSON-RPC errors (`-32001`) the model sees.
They are not transport failures, so the client does not retry them.

A starter action policy:

```yaml
# agw-actions.yaml
tenant: local
version: "1"
rules:
  - id: read-only
    effect: allow
    agents: [my-agent]
    actions: ["mcp.tool.read_file", "mcp.tool.list_directory", "mcp.method.*"]
    max_risk_class: destructive
  - id: never-delete
    effect: deny            # deny overrides any allow
    agents: ["*"]
    actions: ["mcp.tool.delete_file"]
```

Check it with `agw policy lint agw-actions.yaml`, and ask about a specific
call with `agw policy explain --policy agw-actions.yaml --agent my-agent
--action mcp.tool.write_file`.

### Local (stdio) servers: one change to the client config

Put `agw mcp … --` in front of the server's command. Everything after `--` is
the original command, unchanged.

**Claude Desktop** (`claude_desktop_config.json`), **Cursor**
(`.cursor/mcp.json`), and a project **`.mcp.json`**:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agw",
      "args": ["mcp", "--policy", "/abs/path/agw-actions.yaml", "--agent", "my-agent", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/abs/path/workspace"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add filesystem -- agw mcp --policy /abs/path/agw-actions.yaml --agent my-agent -- \
  npx -y @modelcontextprotocol/server-filesystem /abs/path/workspace
```

**VS Code** (`.vscode/mcp.json`) uses `"servers"` rather than `"mcpServers"`,
with the same `command` and `args`.

Use absolute paths: desktop clients start servers from a working directory you
did not choose. For the same reason the evidence goes to
`~/.agw/evidence/mcp-<agent>-<time>.jsonl` unless you pass `--evidence`, and
all of agw's own output goes to stderr, which clients show in the server's log.

### HTTP servers

```bash
agw mcp --policy agw-actions.yaml --agent my-agent --upstream http://localhost:3000/mcp
```

Then point the client at `http://127.0.0.1:8900`.

### Tool redefinition (the rug pull)

`agw` hashes each tool's name, description and schema from `tools/list` and
records any change. A server that is approved and then changes what a tool
claims to do is the attack the MCP threat literature centres on. Add
`--pin-tools` to refuse every tool call after such a change, not just record
it.

**What this rung does not do:** the agent reaches the server through agw
because it was configured to. A compromised agent can start the server itself.
Rung 3 is where that stops being a choice.

---

## Linux host: `agw run`

```bash
sudo agw run --policy agw-policy.yaml --env OPENAI_API_KEY -- python agent.py
```

The command runs in its own network namespace. Its only route out is a proxy
that enforces the egress policy, and an nftables firewall that the workload
cannot modify, even as root, backs that up. The cloud metadata endpoint,
link-local, private and NAT64 space are refused whatever the policy says.

**Environment:** nothing from your shell crosses except `PATH`, `HOME`, locale
and terminal settings. Name what the agent needs with `--env NAME` (repeatable)
or `--env NAME=value`. `--inherit-env` passes everything, secrets included, and
says so.

**Kill switch:** `sudo agw suspend --workload ID` refuses new connections and
closes open ones, with the teardown latency recorded in the evidence.

---

## Docker Compose

[`integrations/docker-sidecar`](../integrations/docker-sidecar): the agent
shares a network namespace with the `agw` container, and a one-shot init step
lets only the proxy's UID out.

```bash
cd integrations/docker-sidecar
docker compose run --rm agent     # start agw, install the rule, run the agent once
docker compose up -d              # or keep a long-running agent up
docker compose down -v
```

It uses the published `ghcr.io/aryan22g/agw` image; set `AGW_IMAGE` to use
your own build.

Replace the `agent` service's image and command with yours. **Keep
`cap_drop: [ALL]`**: with `NET_ADMIN` the agent could delete the rule, and
with `SETUID` it could take the proxy's UID. `test.sh` runs this compose file
against an agent with root that tries both. Both fail.

---

## Kubernetes

[`integrations/kubernetes`](../integrations/kubernetes):

```bash
kubectl apply -f integrations/kubernetes/admission-policy.yaml   # once per cluster, 1.30+
kubectl apply -f integrations/kubernetes/confined-agent.yaml
```

The pod runs `agw sidecar-init` as its first init container, then `agw proxy`
as a native sidecar (Kubernetes 1.29+), then your container. The admission
policy rejects any pod labelled `agw.dev/confined: "true"` whose other
containers keep capabilities, run as the proxy's UID or allow privilege
escalation. It also rejects pods that use `hostNetwork`, and ephemeral debug
containers added later. So the sidecar's security depends on the cluster, not
on whoever wrote the pod spec.

`test.sh` creates a kind cluster, runs a root attacker in the pod, verifies
the live proxy's evidence without stopping it, and checks that each
misconfiguration is refused.

For evidence you need to keep, mount a PersistentVolumeClaim at `/evidence`,
and hold the checkpoint key outside the pod (`--key unix:/path/to/ags-signd.sock`).

---

## GitHub Actions

```yaml
- uses: Aryan22g/agw/integrations/github-action@v0.1.0
  with:
    policy: eval/egress.yaml
    command: python run_eval.py --tasks 400
    env: OPENAI_API_KEY
```

The step fails if the command fails or the evidence does not verify. The
evidence, its public key and a summary of every refusal are uploaded. A
reviewer checks them offline with `agw-verify`.

---

## Anything else

The evidence format is specified in
[RFC-0009](rfcs/RFC-0009-evidence-chain-format.md) with a
[conformance corpus](../conformance/README.md), so another system can produce
or verify it without this code. `agw audit export --format aat` converts a
verified chain into IETF
[agent-audit-trail-04](aat-mapping.md) records for tooling that speaks that
draft.
