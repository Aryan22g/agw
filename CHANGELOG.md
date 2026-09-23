# Changelog

## v0.1.3

- The container images for earlier tags could no longer be pulled: their
  per-architecture images were removed from the registry. This release
  publishes the image again; use `ghcr.io/aryan22g/agw:v0.1.3` or `latest`.
- `ags-signd`, the key-custody daemon the documentation describes, now ships
  in the release archives, the install script and the image. The install
  script still installs older releases, which do not include it.
- The release workflow can be re-run after a failure without first deleting
  the release.
- Documentation: how to install the Python and Go SDKs, how to keep a
  checkpoint as an anchor, and the exact client URL for `agw mcp` over HTTP.

## v0.1.2

- The container image carries the standard OCI labels and annotations
  (source, description, license, version, revision, build date), so
  `ghcr.io/aryan22g/agw` is linked to this repository and shows its
  description and license. The build date is the commit's, not the build's.
- The Docker Compose example uses the published image and a command that
  works as written (`docker compose run --rm agent`); the website's Compose
  and Kubernetes snippets no longer assume a clone.

## v0.1.1

- Verifiers no longer call an empty evidence log "VERIFIED". It contains
  nothing to verify, and an empty log is also what deleting every record
  produces; only a kept checkpoint (`--anchor`) tells the two apart.
  `agw audit verify`, `ags audit verify`, `agw-verify`, bundle verification
  and the website now say **EMPTY**. The result is otherwise unchanged:
  `intact` is true and the exit status is 0. RFC-0009 §6.4 now requires this.
- The website's verifier treated an empty file as no file at all and asked
  for one again. It now reports it.
- `agw version` from `go install ...@vX.Y.Z` reported `dev (commit unknown)`.
  It now reports the module version.

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
