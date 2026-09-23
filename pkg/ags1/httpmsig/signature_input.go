// Package httpmsig builds and parses the AGS1 Signature-Input and Signature
// headers, and drives signing and verification.
package httpmsig

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/nonce"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// SignatureInput is a parsed Signature-Input header.
type SignatureInput struct {
	// Label is the structured-field label, e.g. "sig1".
	Label string

	// Components is the covered component list, in declared order.
	Components []string

	// StrictComponents holds the components that carried the `sf`
	// parameter, so the declared form can be reproduced byte-exactly when
	// rebuilding the signature base.
	StrictComponents map[string]bool

	Params canonicalhttp.SignatureParams
}

// BuildSignatureInput renders a Signature-Input header value.
func BuildSignatureInput(label string, components []string, params canonicalhttp.SignatureParams) (string, error) {
	if strings.TrimSpace(label) == "" {
		label = protocol.DefaultSignatureLabel
	}
	if params.Tag == "" {
		params.Tag = protocol.SignatureTag
	}

	quoted := make([]string, 0, len(components))
	for _, c := range components {
		if protocol.RequiresStrictSerialization(c) {
			quoted = append(quoted, fmt.Sprintf("%q;%s", c, protocol.ParamStrictSerialization))
			continue
		}
		quoted = append(quoted, fmt.Sprintf("%q", c))
	}

	return fmt.Sprintf(`%s=(%s);created=%d;keyid=%q;nonce=%q;tag=%q`,
		label,
		strings.Join(quoted, " "),
		params.Created,
		params.KeyID,
		params.Nonce,
		params.Tag,
	), nil
}

// ParseSignatureInput parses and validates a Signature-Input header value.
//
// The parser is strict and closed: it accepts exactly the four parameters
// AGS1 permits and rejects everything else, including `alg`. A tolerant parser
// here would be a downgrade vector, since anything it silently ignores is
// something the signer believed it was communicating.
func ParseSignatureInput(value string) (*SignatureInput, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("%w: empty header", protocol.ErrMalformedSignatureInput)
	}

	label, rest, err := splitLabel(value)
	if err != nil {
		return nil, err
	}

	inner, params, err := splitInnerList(rest)
	if err != nil {
		return nil, err
	}

	components, strict, err := parseComponents(inner)
	if err != nil {
		return nil, err
	}

	parsed, err := parseParams(params)
	if err != nil {
		return nil, err
	}

	if parsed.Tag != protocol.SignatureTag {
		return nil, fmt.Errorf("%w: got %q, want %q",
			protocol.ErrInvalidTag, parsed.Tag, protocol.SignatureTag)
	}

	// Nonce bounds are a profile constraint (RFC-0002 section 11), so they
	// are enforced at parse time rather than only in ParseHeaders. The nonce
	// becomes part of a replay-store key, and a caller reaching for this
	// parser directly should not be able to skip that check.
	if err := nonce.Validate(parsed.Nonce); err != nil {
		return nil, err
	}

	return &SignatureInput{
		Label:            label,
		Components:       components,
		StrictComponents: strict,
		Params:           parsed,
	}, nil
}

// splitLabel separates "sig1" from "(...);created=...".
func splitLabel(v string) (label string, rest string, err error) {
	i := strings.IndexByte(v, '=')
	if i <= 0 {
		return "", "", fmt.Errorf("%w: missing label", protocol.ErrMalformedSignatureInput)
	}

	label = strings.TrimSpace(v[:i])
	if label == "" {
		return "", "", fmt.Errorf("%w: empty label", protocol.ErrMalformedSignatureInput)
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", "", fmt.Errorf("%w: invalid character %q in label",
				protocol.ErrMalformedSignatureInput, r)
		}
	}

	return label, strings.TrimSpace(v[i+1:]), nil
}

// splitInnerList separates the parenthesised component list from the trailing
// parameters.
func splitInnerList(v string) (inner string, params string, err error) {
	if !strings.HasPrefix(v, "(") {
		return "", "", fmt.Errorf("%w: expected '(' after label", protocol.ErrMalformedSignatureInput)
	}

	closeIdx := strings.IndexByte(v, ')')
	if closeIdx < 0 {
		return "", "", fmt.Errorf("%w: unterminated component list", protocol.ErrMalformedSignatureInput)
	}

	return v[1:closeIdx], strings.TrimSpace(v[closeIdx+1:]), nil
}

// parseComponents parses the inner list, honouring quoted identifiers and the
// `sf` parameter.
func parseComponents(inner string) ([]string, map[string]bool, error) {
	fields := strings.Fields(inner)
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("%w: empty component list", protocol.ErrMalformedSignatureInput)
	}

	components := make([]string, 0, len(fields))
	strict := make(map[string]bool, len(fields))

	for _, f := range fields {
		name := f
		var param string

		if i := strings.IndexByte(f, ';'); i >= 0 {
			name = f[:i]
			param = f[i+1:]
		}

		if !strings.HasPrefix(name, `"`) || !strings.HasSuffix(name, `"`) || len(name) < 3 {
			return nil, nil, fmt.Errorf("%w: component %q must be a quoted string",
				protocol.ErrMalformedSignatureInput, f)
		}
		name = name[1 : len(name)-1]

		if !protocol.IsSupportedComponent(name) {
			return nil, nil, fmt.Errorf("%w: %q", protocol.ErrUnsupportedComponent, name)
		}

		switch param {
		case "":
			if protocol.RequiresStrictSerialization(name) {
				return nil, nil, fmt.Errorf("%w: %q must carry ;sf",
					protocol.ErrMissingStrictParam, name)
			}
		case protocol.ParamStrictSerialization:
			if !protocol.RequiresStrictSerialization(name) {
				return nil, nil, fmt.Errorf("%w: %q must not carry ;sf",
					protocol.ErrMalformedSignatureInput, name)
			}
			strict[name] = true
		default:
			return nil, nil, fmt.Errorf("%w: unknown component parameter %q on %q",
				protocol.ErrMalformedSignatureInput, param, name)
		}

		components = append(components, name)
	}

	return components, strict, nil
}

// parseParams parses ";created=...;keyid=...;nonce=...;tag=..." and enforces
// the closed parameter set.
func parseParams(v string) (canonicalhttp.SignatureParams, error) {
	var out canonicalhttp.SignatureParams

	if v == "" {
		return out, fmt.Errorf("%w: missing signature parameters", protocol.ErrMalformedSignatureInput)
	}

	seen := make(map[string]bool, 4)

	for _, part := range splitParams(v) {
		key, raw, ok := strings.Cut(part, "=")
		if !ok {
			return out, fmt.Errorf("%w: parameter %q is not key=value",
				protocol.ErrMalformedSignatureInput, part)
		}

		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)

		if seen[key] {
			return out, fmt.Errorf("%w: %q", protocol.ErrDuplicateParameter, key)
		}
		seen[key] = true

		switch key {
		case "created":
			created, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return out, fmt.Errorf("%w: created must be unix seconds, got %q",
					protocol.ErrMalformedSignatureInput, raw)
			}
			out.Created = created

		case "keyid":
			out.KeyID = unquote(raw)

		case "nonce":
			out.Nonce = unquote(raw)

		case "tag":
			out.Tag = unquote(raw)

		case "alg":
			return out, protocol.ErrAlgorithmNotOnTheWire

		default:
			return out, fmt.Errorf("%w: %q", protocol.ErrForbiddenParameter, key)
		}
	}

	if !seen["created"] {
		return out, protocol.ErrMissingCreated
	}
	if !seen["keyid"] || out.KeyID == "" {
		return out, protocol.ErrMissingKeyID
	}
	if !seen["nonce"] || out.Nonce == "" {
		return out, protocol.ErrMissingNonce
	}
	if !seen["tag"] || out.Tag == "" {
		return out, protocol.ErrMissingTag
	}

	return out, nil
}

// splitParams splits on ';' while ignoring separators inside quoted strings,
// so that a nonce or keyid containing ';' cannot break the parse.
func splitParams(v string) []string {
	var (
		parts   []string
		current strings.Builder
		inQuote bool
	)

	for _, r := range v {
		switch {
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ';' && !inQuote:
			if s := strings.TrimSpace(current.String()); s != "" {
				parts = append(parts, s)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}

	if s := strings.TrimSpace(current.String()); s != "" {
		parts = append(parts, s)
	}

	return parts
}

func unquote(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		return v[1 : len(v)-1]
	}
	return v
}
