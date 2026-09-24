// Package evidence is the reference implementation of the agw evidence chain,
// specified in RFC-0009 (docs/rfcs/RFC-0009-evidence-chain-format.md).
//
// An EvidenceSink appends records to a JSON Lines file, each linked to the one
// before it by a hash, and signs periodic checkpoints over the chain with
// Ed25519. Verify and VerifyWithAnchor check a log with nothing but the file
// and a public key; Export and VerifyBundle produce and check a self-contained
// bundle for an auditor. The conformance corpus in conformance/evidence pins
// the format, and this package, cmd/agw-verify and the website's verifier all
// pass it.
//
// This is a public package of github.com/Aryan22g/agw. It is at v0: a
// breaking change is possible between minor releases, and is listed in
// CHANGELOG.md when it happens. The chain format itself changes only with a
// new version string (ChainVersion).
package evidence
