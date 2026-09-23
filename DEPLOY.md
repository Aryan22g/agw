# Deploying

agw is one static binary (`watch`, `mcp`, `run`, `proxy`, `sidecar-init`), or
the `ghcr.io/aryan22g/agw` image. There is no database and no service to run
beyond it. Every environment has a tested recipe in
**[docs/integrations.md](docs/integrations.md)**: a Linux host (`agw run`),
Docker Compose and Kubernetes (sidecar), GitHub Actions, MCP clients and
OpenTelemetry pipelines.

Before production, decide three things:

1. **Where the checkpoint key lives.** The default,
   `~/.agw/checkpoint.key`, is on the same machine as the evidence it signs.
   Someone who controls that machine can sign a forged history. Run
   `ags-signd` somewhere the enforcement point's compromise does not reach,
   and pass `--key unix:/path/to/sock`.
2. **Where evidence is kept.** It is written as append-only JSON Lines. Ship it
   to storage with a retention lock, and keep the public key, plus a
   checkpoint from each period, somewhere else. Six months is the EU AI Act
   minimum; see [docs/compliance](docs/compliance/eu-ai-act-article-12.md).
3. **Which rung.** Start at 0 or 1 in production and rehearse before you
   enforce. `agw policy suggest` drafts a policy from what was observed.
