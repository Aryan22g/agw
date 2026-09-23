package signer

import (
	"encoding/base64"
	"encoding/json"
)

// Wire protocol between a client and a signing daemon.
//
// Deliberately minimal. The daemon holds the key and is the last line of
// defence if the gateway is compromised, so its parser is attack surface that
// should be small enough to read in one sitting. There is no export
// operation, no key-management operation, and no way to ask it for anything
// but a signature over bytes the caller supplies.
const (
	// OpSign requests a signature.
	OpSign = "sign"

	// OpDescribe returns the key id and public key.
	OpDescribe = "describe"

	// MaxMessageBytes bounds a single signing request. Signature bases and
	// audit checkpoint inputs are well under a kilobyte; the limit exists so
	// a compromised gateway cannot use the daemon as a memory amplifier.
	MaxMessageBytes = 64 << 10
)

// Request is one operation.
type Request struct {
	Op string `json:"op"`

	// Message is base64 for OpSign.
	Message string `json:"message,omitempty"`

	// Purpose optionally declares what the message is. It is defence in
	// depth, not the control: the daemon derives the purpose from the
	// message's own bytes and refuses a declared purpose that disagrees. A
	// label an attacker sets cannot be what decides whether to sign.
	Purpose string `json:"purpose,omitempty"`
}

// Response is the daemon's reply.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	// Signature is base64, set for a successful OpSign.
	Signature string `json:"signature,omitempty"`

	// KeyID and PublicKey are set for OpDescribe.
	KeyID     string `json:"keyId,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func writeJSON(enc *json.Encoder, v any) error { return enc.Encode(v) }
