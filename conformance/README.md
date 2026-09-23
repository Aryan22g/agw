# Conformance

Test vectors for the formats this project defines, so that an implementation
written by someone else can be checked without trusting ours.

## `evidence/agw-evidence-v2.json` — RFC-0009 evidence chains

Specification: [`docs/rfcs/RFC-0009-evidence-chain-format.md`](../docs/rfcs/RFC-0009-evidence-chain-format.md).

- `hash_vectors` — single records with the exact canonical hash input and the
  resulting hash. Start here: when your hashes disagree, diff the canonical
  input field by field.
- `verify_vectors` — whole logs, each with the key to use (`"test"` means
  `public_key`; `""` means verify without a key), an optional `anchor`, and the
  result a conformant verifier must report: `intact`, the counts, and every
  problem as `{kind, seq}` in order.

The expected results were written from the specification, not produced by
running a verifier. Three independent verifiers pass every vector:

| Implementation | Language | Dependencies |
|---|---|---|
| `internal/gateway/audit` | Go | reference implementation |
| [`cmd/agw-verify`](../cmd/agw-verify) | Go | standard library only, written from RFC-0009 |
| [`site/assets/rfc0009.js`](../site/assets/rfc0009.js) | JavaScript | none; WebCrypto. Runs in the browser on the project site |

They are also run against each other on thousands of randomly mutated logs
(`go test ./cmd/agw-verify -run Differential`, which includes the JavaScript
verifier when Node is installed; `node site/test/conformance.mjs` runs the
corpus against it alone); that search is what found the
case-insensitive member attack described in RFC-0009 §1, and the corpus
records it as `case_variant_member`.

The signing key is `Ed25519(SHA-256(key_seed))`. The seed is published in the
file, so the key is public and must never sign real evidence. A test fails if
the corpus is regenerated with any other key.

If you implement a verifier and it disagrees with a vector, please open an
issue. Either your implementation or the specification is wrong, and both are
worth knowing.

## `../pkg/ags1/vectors/ags1-v1.json` — AGS1 request signing

Specification: [`docs/rfcs/RFC-0002-ags1-request-signing-profile.md`](../docs/rfcs/RFC-0002-ags1-request-signing-profile.md).
