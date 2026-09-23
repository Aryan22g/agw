# Security

This is security software. A vulnerability in it is a hole in someone
else's containment, so reports are handled first.

## Reporting

Report privately through GitHub: **Security → Report a vulnerability** on this
repository. Please do not open a public issue.

Include what you can: the component, a reproduction, and what an attacker
gains. A reproduction as a failing test, or as a gym episode
(`internal/gym/attacks.go`), is the most useful form, because it becomes the
regression test.

You will get an acknowledgement within three working days, and a fix or a
plan within fourteen. We credit reporters in the release notes unless asked
not to.

## Scope

In scope, most important first:

1. **Anything that lets a confined workload reach what policy refuses**:
   `agw run`, the sidecar, the proxy, the structural guard. Including
   anything that needs root inside the sandbox; that is the threat model.
2. **Anything that lets evidence verify when it should not**, or not verify
   when it should: the chain, checkpoints, anchors, `agw-verify`, RFC-0009
   itself.
3. **Anything that lets a refused MCP tool call through, or an AGS1
   signature verify when it should not**, including messages two parsers
   read differently.
4. **Key custody**: the checkpoint and assertion keys, `ags-signd`.

Out of scope: what [docs/coverage.md](docs/coverage.md) already says is not
stopped, such as harm within a permitted scope, or exfiltration to a
permitted destination. Improvements there are welcome as issues.

## What has been found so far

We publish these because the way to trust a security product is to see how
its failures were found and fixed. Each was found by the project's own
adversarial testing, and each is pinned by a test.

| Found by | Issue |
|---|---|
| gym | `permit_private` could exempt the cloud metadata range |
| gym | an evidence chain with no checkpoints verified clean |
| differential testing of two verifiers | case-insensitive JSON member matching let a verified log display a decision other than the one signed |
| parser-differential test | `{"method":"tools/call","Method":"initialize",...}` was authorized as `initialize` and executed as a forbidden tool call |
| end-to-end `agw run` on Linux | the workload inherited the supervisor's environment, including its credentials |
| review of the MCP enforcement point | allowed tool calls were forwarded when their evidence record could not be written (not fail-closed) |
| end-to-end test of separate key custody | the signing daemon refused every v2 checkpoint, so separate custody of the checkpoint key failed at the first checkpoint |
