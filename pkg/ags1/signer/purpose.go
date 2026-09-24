package signer

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// A signing daemon holds a key the gateway does not. That makes socket access
// to it a more attractive objective than the key file itself -- and in the
// July 2026 Hugging Face intrusion, minting correctly-signed tokens with a
// stolen signing key is exactly what turned code execution into a full
// compromise.
//
// A daemon that signs whatever bytes it is handed is an unlimited signing
// oracle for anything that reaches the socket: a checkpoint, a principal
// assertion, a token in an entirely different protocol. Purposes bound that.
// The daemon signs only byte strings whose own leading bytes declare a purpose
// it serves, and only when the rest of the message parses as that purpose's
// canonical form.
//
// This does not make socket access harmless. An attacker who has it can still
// obtain signatures over well-formed assertions. What it removes is the
// ability to obtain a signature over anything else, which is the difference
// between a bounded forgery and a general-purpose key.
const (
	// PurposePrincipalContext is the gateway's signed statement about a
	// verified principal, carried to a backend in X-AGW-* headers: the prefix
	// "agw-principal-context-v1\n", then each field as length-prefixed
	// lowercase name and value, sorted by name.
	PurposePrincipalContext = "principal-context"

	// PurposeEvidenceCheckpoint pins the head of an evidence chain.
	// See pkg/evidence.canonicalCheckpointInput.
	PurposeEvidenceCheckpoint = "evidence-checkpoint"

	// PurposeReadinessProbe proves the signing path works end to end.
	//
	// Readiness cannot be established by asking the daemon to describe
	// itself: a KMS- or HSM-backed signer can answer that from cache while
	// being unable to sign. Exercising the real path is the only honest
	// check.
	//
	// The message is a fixed constant with no variable part, so a signature
	// over it is the same bytes every time and conveys nothing. It is not a
	// valid assertion or checkpoint, so it cannot be repurposed.
	PurposeReadinessProbe = "readiness-probe"
)

// ReadinessProbeMessage is the entire, exact message a readiness probe may
// sign. Callers must use this value rather than constructing their own.
var ReadinessProbeMessage = []byte(prefixReadinessProbe + "readiness")

// Domain prefixes, as they appear at the start of each canonical form. These
// are duplicated here rather than imported because pkg/ags1 must not depend on
// internal/: the constants are part of a frozen wire format, and a test below
// fails if either side drifts.
const (
	prefixPrincipalContext = "agw-principal-context-v1\n"
	// Checkpoints carry the chain version in their prefix. v2 is what every
	// producer writes; v1 is kept so a daemon can still countersign for a
	// chain that has not migrated. Accepting only v1 -- which is what this
	// did after the format moved to v2 -- made the daemon refuse every
	// checkpoint, so separate custody of the checkpoint key failed at the
	// first checkpoint, and a fail-closed gateway with it.
	prefixEvidenceCheckpoint   = "agw-evidence-v2/checkpoint\n"
	prefixEvidenceCheckpointV1 = "agw-evidence-v1/checkpoint\n"
	prefixReadinessProbe       = "agw-readiness-probe-v1\n"
)

var (
	// ErrUnknownPurpose is returned when a message does not begin with a
	// domain prefix this daemon serves. It is the refusal that matters: it
	// is what stops the daemon being used to sign an arbitrary blob.
	ErrUnknownPurpose = errors.New("signer: message does not declare a purpose this daemon serves")

	// ErrMalformedForPurpose is returned when a message declares a known
	// purpose but does not parse as that purpose's canonical form.
	ErrMalformedForPurpose = errors.New("signer: message is malformed for its declared purpose")

	// ErrPurposeMismatch is returned when a caller declares one purpose and
	// the message's own bytes declare another.
	ErrPurposeMismatch = errors.New("signer: declared purpose does not match the message")

	// ErrRateLimited is returned when a purpose exceeds its signing budget.
	ErrRateLimited = errors.New("signer: signing rate limit exceeded for this purpose")
)

// ClassifyPurpose derives a message's purpose from its own leading bytes.
//
// Deriving rather than trusting a caller-supplied label is deliberate: a
// label is something an attacker sets, while the prefix is part of the bytes
// the signature will actually cover.
func ClassifyPurpose(message []byte) (string, error) {
	s := string(message)

	switch {
	case strings.HasPrefix(s, prefixPrincipalContext):
		return PurposePrincipalContext, nil
	case strings.HasPrefix(s, prefixEvidenceCheckpoint), strings.HasPrefix(s, prefixEvidenceCheckpointV1):
		return PurposeEvidenceCheckpoint, nil
	case strings.HasPrefix(s, prefixReadinessProbe):
		return PurposeReadinessProbe, nil
	default:
		return "", fmt.Errorf("%w", ErrUnknownPurpose)
	}
}

// ValidateForPurpose checks that a message parses as its purpose's canonical
// form.
//
// The prefix check alone would let an attacker append arbitrary bytes to a
// valid prefix and have them signed. Parsing the remainder closes that: every
// byte after the prefix has to be accounted for by the length-prefixed
// encoding, so there is nowhere to hide a payload.
func ValidateForPurpose(purpose string, message []byte) error {
	switch purpose {
	case PurposePrincipalContext:
		body := strings.TrimPrefix(string(message), prefixPrincipalContext)
		fields, err := parseLengthPrefixed(body)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedForPurpose, err)
		}
		if len(fields) == 0 || len(fields)%2 != 0 {
			return fmt.Errorf("%w: principal context has %d parts, expected key/value pairs",
				ErrMalformedForPurpose, len(fields))
		}
		// The assertion is worthless without an identity to assert, and a
		// daemon asked to sign one without it is being misused.
		required := []string{"x-agw-verified-tenant-id", "x-agw-verified-agent-id", "x-agw-decision-id"}
		present := make(map[string]bool, len(fields)/2)
		for i := 0; i < len(fields); i += 2 {
			present[fields[i]] = true
		}
		for _, k := range required {
			if !present[k] {
				return fmt.Errorf("%w: principal context is missing %s", ErrMalformedForPurpose, k)
			}
		}
		return nil

	case PurposeEvidenceCheckpoint:
		body, ok := strings.CutPrefix(string(message), prefixEvidenceCheckpoint)
		if !ok {
			body, ok = strings.CutPrefix(string(message), prefixEvidenceCheckpointV1)
		}
		if !ok {
			return fmt.Errorf("%w: not a checkpoint", ErrMalformedForPurpose)
		}
		parts, err := parseLengthPrefixed(body)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedForPurpose, err)
		}
		// seq, hash, count, issuedAt, keyID
		if len(parts) != 5 {
			return fmt.Errorf("%w: checkpoint has %d parts, expected 5",
				ErrMalformedForPurpose, len(parts))
		}
		if _, err := strconv.ParseUint(parts[0], 10, 64); err != nil {
			return fmt.Errorf("%w: checkpoint seq %q is not a number", ErrMalformedForPurpose, parts[0])
		}
		if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil {
			return fmt.Errorf("%w: checkpoint count %q is not a number", ErrMalformedForPurpose, parts[2])
		}
		return nil

	case PurposeReadinessProbe:
		// Exact match, not a prefix check. A probe with anything appended is
		// a caller trying to get arbitrary bytes signed under the one purpose
		// whose contents are not otherwise constrained.
		if !bytes.Equal(message, ReadinessProbeMessage) {
			return fmt.Errorf("%w: readiness probe must be the exact constant message",
				ErrMalformedForPurpose)
		}
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnknownPurpose, purpose)
	}
}

// parseLengthPrefixed decodes the "<len>:<value>" encoding both canonical
// forms use, and requires that the input is consumed exactly.
//
// The trailing-bytes check is the point of this function. Without it a caller
// could append anything after a well-formed body and have it signed along with
// the legitimate content.
func parseLengthPrefixed(s string) ([]string, error) {
	var out []string

	for len(s) > 0 {
		colon := strings.IndexByte(s, ':')
		if colon <= 0 {
			return nil, fmt.Errorf("expected <len>: at offset, got %q", truncateForError(s))
		}
		n, err := strconv.Atoi(s[:colon])
		if err != nil {
			return nil, fmt.Errorf("bad length prefix %q", s[:colon])
		}
		if n < 0 {
			return nil, fmt.Errorf("negative length %d", n)
		}
		s = s[colon+1:]
		if n > len(s) {
			return nil, fmt.Errorf("length %d overruns the remaining %d bytes", n, len(s))
		}
		out = append(out, s[:n])
		s = s[n:]
	}

	return out, nil
}

func truncateForError(s string) string {
	const max = 24
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
