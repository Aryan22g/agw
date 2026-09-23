// Package strictjson closes the gap between how Go reads JSON and how
// everything else does.
//
// encoding/json matches member names case-INSENSITIVELY and, when a name
// repeats, keeps the last value. JavaScript's JSON.parse and Python's json
// match case-sensitively; some parsers keep the first duplicate, some reject
// it. Wherever this code makes a security decision about a JSON message that
// something else will also read -- a verifier and a reviewer's tooling, an
// enforcement point and the MCP server behind it -- that difference is a way
// to show one reader one message and the other a different one.
//
// It was found twice. In the evidence verifier, a verified log could display
// a different decision from the one that was signed. In the MCP enforcement
// point it was a policy bypass: {"method":"tools/call","Method":"initialize",
// ...} was authorized as initialize and executed by the server as a tool call
// the policy forbade.
//
// The rule applied here is RFC 7493 (I-JSON) for duplicates, plus: a member
// whose name equals a name the caller relies on except for letter case is
// refused, because readers disagree about which one it is.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrDuplicate reports an object that names the same member twice.
var ErrDuplicate = errors.New("duplicate member name")

// ErrCaseVariant reports a member name that differs from a relied-on name
// only by letter case.
var ErrCaseVariant = errors.New("member name differs from a defined name only by case")

// NoDuplicates rejects a document in which any object, at any depth, repeats
// a member name. The document may be a single value or, as for a JSON-RPC
// batch, an array of them.
func NoDuplicates(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walk(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func walk(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			kt, err := d.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			if _, dup := seen[k]; dup {
				return fmt.Errorf("%w %q", ErrDuplicate, k)
			}
			seen[k] = struct{}{}
			if err := walk(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := walk(d); err != nil {
				return err
			}
		}
	}
	_, err = d.Token() // the closing delimiter
	return err
}

// ExactNames rejects an object that carries a member whose name equals one of
// defined except for letter case.
func ExactNames(obj map[string]json.RawMessage, defined ...string) error {
	for k := range obj {
		for _, d := range defined {
			if k != d && strings.EqualFold(k, d) {
				return fmt.Errorf("%w: %q (defined: %q)", ErrCaseVariant, k, d)
			}
		}
	}
	return nil
}
