# Changelog

## v0.1.0 — first public release

### Containment plane: `agw`
- `agw init`: a checkpoint key in `~/.agw`, a starter policy, and what to run
  next.
- Rung 0–1, `agw watch`: OpenTelemetry in (HTTP/JSON, HTTP/protobuf, gRPC,
  gzipped or not) as signed evidence; with `--policy`, what enforcement
  *would* refuse. `agw policy suggest` drafts a policy from what was seen,
  and never drafts the cloud metadata endpoint.
- Rung 2, `agw mcp`: MCP tool calls checked before the server sees them,
  over HTTP or in front of a stdio server (`agw mcp ... -- CMD`). Messages
  two JSON parsers would read differently are refused. `--pin-tools` stops
  calls after a tool redefinition.
- Rung 3, `agw run`: default-deny egress in a network namespace that holds
  against root; the metadata endpoint refused whatever policy says; no
  inherited environment unless granted with `--env`. `agw suspend` cuts
  connections, refuses new ones and kills the process group, with 100 ms
  asserted in CI.
- `agw proxy` and `agw sidecar-init` for Docker, Kubernetes and VMs.
- Fail closed everywhere it enforces: an action whose evidence cannot be
  written does not happen.

### Evidence
- RFC-0009, the evidence chain format: hash-chained records, signed
  checkpoints, anchors for rollback detection.
- A 39-vector conformance corpus and three independent verifiers: the
  reference, `agw-verify` (one file, standard library only, no sockets) and
  the website's in-browser verifier, cross-checked by differential testing.
- `agw audit verify | show | export | verify-bundle`, `agw tail`, and export
  to the IETF agent-audit-trail draft (`--format aat`).
- Checkpoint keys held by a separate `ags-signd` with `--key unix:SOCKET`.

### Signed requests: AGS1
- RFC-0002, an RFC 9421 profile for agent request signing, frozen in
  `pkg/ags1`, with a conformance corpus.
- Go and Python SDKs, byte-identical on every vector; the `ags` CLI.

### Integrations
- Kubernetes (native sidecar and a ValidatingAdmissionPolicy), Docker
  Compose, a GitHub Action, MCP clients, OpenTelemetry pipelines. Each tested
  against the real component, and containment against an agent with root.

### Distribution
- Archives for five platforms with `SHA256SUMS` and build-provenance
  attestations; a multi-architecture image at `ghcr.io/aryan22g/agw`; an
  install script that verifies the checksum before installing anything.
- Licensed under the Apache License 2.0.
