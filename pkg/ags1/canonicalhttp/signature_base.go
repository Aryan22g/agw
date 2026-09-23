package canonicalhttp

import (
	"fmt"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// SignatureParams are the RFC 9421 signature parameters AGS1 permits.
//
// There is deliberately no Alg field. AGS1 forbids `alg` on the wire: the
// algorithm is resolved from the registered credential, so a caller cannot
// nominate one. A verifier that trusts a wire-supplied algorithm can be
// steered toward a weaker primitive, or toward "none".
type SignatureParams struct {
	Created int64
	KeyID   string
	Nonce   string
	Tag     string
}

// BuildSignatureBase constructs the exact bytes that are signed and verified.
//
// The component list is not taken on trust from the caller: it must match the
// AGS1 profile for this request exactly, in order. Accepting an arbitrary
// subset would let a signer omit, say, @path or content-digest and still
// produce a signature the verifier accepts -- which would mean the signature
// covers less than the verifier believes it does.
func BuildSignatureBase(
	req *CanonicalRequest,
	components []string,
	params SignatureParams,
) ([]byte, error) {
	if req == nil {
		return nil, protocol.ErrNilRequest
	}
	if err := ValidateCoveredComponents(components, req.HasBody()); err != nil {
		return nil, err
	}

	lines := make([]string, 0, len(components)+1)

	for _, component := range components {
		line, err := BuildComponentLine(req, component)
		if err != nil {
			return nil, err
		}
		lines = append(lines, line)
	}

	lines = append(lines, BuildSignatureParamsLine(components, params))

	return []byte(strings.Join(lines, "\n")), nil
}

// ValidateCoveredComponents checks a declared component list against the AGS1
// profile for this request shape.
func ValidateCoveredComponents(components []string, hasBody bool) error {
	required := protocol.CoveredComponents(hasBody)

	if len(components) != len(required) {
		return fmt.Errorf("%w: got %d components, AGS1 requires %d for a %s request",
			protocol.ErrComponentSetMismatch, len(components), len(required),
			bodyDescription(hasBody))
	}

	seen := make(map[string]struct{}, len(components))
	for i, c := range components {
		if _, dup := seen[c]; dup {
			return fmt.Errorf("%w: %q", protocol.ErrDuplicateComponent, c)
		}
		seen[c] = struct{}{}

		if !protocol.IsSupportedComponent(c) {
			return fmt.Errorf("%w: %q", protocol.ErrUnsupportedComponent, c)
		}
		if c != required[i] {
			return fmt.Errorf("%w: position %d is %q, AGS1 requires %q",
				protocol.ErrComponentSetMismatch, i, c, required[i])
		}
	}

	return nil
}

func bodyDescription(hasBody bool) string {
	if hasBody {
		return "body-bearing"
	}
	return "body-less"
}

// BuildComponentLine renders one component line of the signature base.
//
// Derived components resolve from the request line; everything else resolves
// from a header. Content-Digest carries the `sf` parameter and is re-serialized
// into strict structured-field form before comparison, so incidental
// whitespace introduced by an intermediary does not break an otherwise valid
// signature.
func BuildComponentLine(req *CanonicalRequest, component string) (string, error) {
	value, err := ResolveComponentValue(req, component)
	if err != nil {
		return "", err
	}

	if protocol.RequiresStrictSerialization(component) {
		return fmt.Sprintf("%q;%s: %s", component, protocol.ParamStrictSerialization, value), nil
	}
	return fmt.Sprintf("%q: %s", component, value), nil
}

// ResolveComponentValue resolves the canonical value for one covered
// component.
func ResolveComponentValue(req *CanonicalRequest, component string) (string, error) {
	if req == nil {
		return "", protocol.ErrNilRequest
	}

	switch component {
	case protocol.ComponentMethod:
		return req.Method, nil
	case protocol.ComponentAuthority:
		return req.Authority, nil
	case protocol.ComponentPath:
		return req.Path, nil
	case protocol.ComponentQuery:
		return req.Query, nil
	}

	if !protocol.IsSupportedComponent(component) {
		return "", fmt.Errorf("%w: %q", protocol.ErrUnsupportedComponent, component)
	}

	value, ok := req.Headers[NormalizeHeaderName(component)]
	if !ok {
		return "", fmt.Errorf("%w: %q", protocol.ErrMissingCoveredComponent, component)
	}

	if component == protocol.ComponentContentDigest {
		normalized, err := digest.Normalize(value)
		if err != nil {
			return "", err
		}
		return normalized, nil
	}

	return value, nil
}

// BuildSignatureParamsLine renders the trailing @signature-params line.
//
// It MUST be last, and its component list MUST be identical to the lines
// above it. That is what binds the signature to the specific set of
// components covered: without it, an attacker could strip a component line
// and present a shorter base as if it were the original.
func BuildSignatureParamsLine(components []string, params SignatureParams) string {
	quoted := make([]string, 0, len(components))
	for _, c := range components {
		if protocol.RequiresStrictSerialization(c) {
			quoted = append(quoted, fmt.Sprintf("%q;%s", c, protocol.ParamStrictSerialization))
			continue
		}
		quoted = append(quoted, fmt.Sprintf("%q", c))
	}

	return fmt.Sprintf(`"@signature-params": (%s);created=%d;keyid=%q;nonce=%q;tag=%q`,
		strings.Join(quoted, " "),
		params.Created,
		params.KeyID,
		params.Nonce,
		params.Tag,
	)
}
