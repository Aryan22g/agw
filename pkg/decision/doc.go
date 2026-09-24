// Package decision is the outcome of an enforcement decision: allow, deny or
// fail, with a stable reason code.
//
// Reason codes are a contract. Evidence records, error responses and the
// SDKs' error types all carry them, so clients can branch on a reason rather
// than on a status code or a message.
//
// This is a public package of github.com/Aryan22g/agw, at v0: a breaking
// change is possible between minor releases and is listed in CHANGELOG.md.
package decision
