package httpmsig

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// BuildSignatureHeader renders a Signature header value in RFC 9421 byte
// sequence form:
//
//	sig1=:BASE64:
func BuildSignatureHeader(label string, signature []byte) string {
	if strings.TrimSpace(label) == "" {
		label = protocol.DefaultSignatureLabel
	}
	return fmt.Sprintf("%s=:%s:", label, base64.StdEncoding.EncodeToString(signature))
}

// ParseSignatureHeader extracts the label and raw signature bytes from a
// Signature header value.
//
// The header is a structured-field dictionary whose value is a byte sequence
// delimited by colons -- NOT a bare base64 string. Feeding the whole header
// value to a base64 decoder is a real and easy mistake: the decoder either
// errors or, worse, silently decodes something that is not the signature.
func ParseSignatureHeader(value string) (label string, signature []byte, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil, fmt.Errorf("%w: empty header", protocol.ErrMalformedSignature)
	}

	i := strings.IndexByte(value, '=')
	if i <= 0 {
		return "", nil, fmt.Errorf("%w: missing label", protocol.ErrMalformedSignature)
	}

	label = strings.TrimSpace(value[:i])
	encoded := strings.TrimSpace(value[i+1:])

	if len(encoded) < 2 || !strings.HasPrefix(encoded, ":") || !strings.HasSuffix(encoded, ":") {
		return "", nil, fmt.Errorf("%w: signature must be a :base64: byte sequence",
			protocol.ErrMalformedSignature)
	}
	encoded = encoded[1 : len(encoded)-1]

	if encoded == "" {
		return "", nil, fmt.Errorf("%w: empty signature", protocol.ErrMalformedSignature)
	}

	signature, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", nil, fmt.Errorf("%w: signature is not valid base64: %v",
			protocol.ErrMalformedSignature, err)
	}

	return label, signature, nil
}

// MatchLabel checks that the Signature and Signature-Input headers refer to
// the same signature.
//
// Mismatched labels mean the two headers describe different signatures, so
// the parameters being validated would not be the parameters that were
// actually signed.
func MatchLabel(inputLabel, signatureLabel string) error {
	if inputLabel != signatureLabel {
		return fmt.Errorf("%w: signature-input label %q does not match signature label %q",
			protocol.ErrMalformedSignature, inputLabel, signatureLabel)
	}
	return nil
}
