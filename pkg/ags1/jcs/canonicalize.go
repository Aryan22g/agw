// Package jcs implements the RFC 8785 JSON Canonicalization Scheme subset
// that AGS1 requires.
//
// AGS1 signs the exact transmitted bytes. For JSON bodies those bytes MUST be
// JCS output, so that an agent in Python and an agent in Go signing the same
// logical payload produce byte-identical input to the digest.
package jcs

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"

	jcslib "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize returns the RFC 8785 canonical form of a JSON document.
//
// Input is rejected -- not repaired -- when it is not valid UTF-8, is not
// well-formed JSON, carries trailing content, or contains duplicate object
// keys. Duplicate keys in particular are ambiguous across parsers: one
// implementation keeps the first value and another keeps the last, so the
// signer and the verifier could canonicalize the same bytes differently.
// Rejecting is the only safe reading.
//
// Unicode is preserved exactly. No NFC or NFKC normalization is applied,
// because normalizing would change the transmitted bytes out from under the
// digest the sender computed.
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, protocol.ErrInvalidJSON
	}
	if !utf8.Valid(input) {
		return nil, protocol.ErrInvalidUTF8
	}

	if err := RejectDuplicateKeys(input); err != nil {
		return nil, err
	}

	// Validate structure, and reject NaN/Infinity, before canonicalizing.
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()

	var doc any
	if err := decoder.Decode(&doc); err != nil {
		return nil, protocol.ErrInvalidJSON
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, protocol.ErrInvalidJSON
	}

	out, err := jcslib.Transform(input)
	if err != nil {
		return nil, protocol.ErrInvalidJSON
	}

	return out, nil
}

// RejectDuplicateKeys walks a JSON document and fails if any object contains
// the same key twice.
//
// encoding/json silently keeps the last occurrence, so this has to be a
// separate streaming pass over the tokens rather than a property of decoding.
func RejectDuplicateKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))

	var parseValue func() error

	parseObject := func() error {
		seen := make(map[string]struct{})

		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return protocol.ErrInvalidJSON
			}

			key, ok := token.(string)
			if !ok {
				return protocol.ErrInvalidJSON
			}
			if _, exists := seen[key]; exists {
				return protocol.ErrDuplicateJSONKey
			}
			seen[key] = struct{}{}

			if err := parseValue(); err != nil {
				return err
			}
		}

		if _, err := decoder.Token(); err != nil { // consume '}'
			return protocol.ErrInvalidJSON
		}
		return nil
	}

	parseArray := func() error {
		for decoder.More() {
			if err := parseValue(); err != nil {
				return err
			}
		}
		if _, err := decoder.Token(); err != nil { // consume ']'
			return protocol.ErrInvalidJSON
		}
		return nil
	}

	parseValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return protocol.ErrInvalidJSON
		}

		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}

		switch delim {
		case '{':
			return parseObject()
		case '[':
			return parseArray()
		default:
			return nil
		}
	}

	return parseValue()
}

// IsCanonical reports whether input is already in RFC 8785 canonical form.
func IsCanonical(input []byte) bool {
	out, err := Canonicalize(input)
	if err != nil {
		return false
	}
	return bytes.Equal(input, out)
}
