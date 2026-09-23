package httpmsig

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/jcs"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/nonce"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// SignInput describes a request to be signed.
type SignInput struct {
	Request *http.Request

	// Body is the request body. For a JSON content type it is canonicalized
	// with JCS before signing, and the canonical bytes replace the request
	// body so that what is signed is exactly what is sent.
	Body []byte

	TenantID string
	AgentID  string

	// RequestID and TraceParent are generated when empty.
	RequestID   string
	TraceParent string

	// Nonce is generated when empty.
	Nonce string

	PrivateKey ed25519.PrivateKey

	// KeyID is derived from the private key when empty.
	KeyID string

	// Created defaults to now.
	Created time.Time

	// Label defaults to "sig1".
	Label string
}

// SignResult reports what was signed, for debugging and golden vectors.
type SignResult struct {
	SignatureInput string
	Signature      string
	SignatureBase  []byte
	ContentDigest  string
	KeyID          string
	Nonce          string
	RequestID      string
	Created        int64
	Body           []byte
}

// Sign applies a complete AGS1 signature to an *http.Request, mutating its
// headers and body in place.
//
// Order matters here. The body is canonicalized first, then digested, then
// the digest header is set, and only then is the signature base built --
// because the base covers the digest header. Computing the digest over
// pre-canonicalization bytes is the classic way to produce a signature that
// verifies nowhere.
func Sign(in SignInput) (*SignResult, error) {
	if in.Request == nil {
		return nil, protocol.ErrNilRequest
	}
	if len(in.PrivateKey) != ed25519.PrivateKeySize {
		return nil, protocol.ErrInvalidPrivateKey
	}
	if in.TenantID == "" || in.AgentID == "" {
		return nil, fmt.Errorf("%w: tenant id and agent id are required",
			protocol.ErrMissingRequiredHeader)
	}

	keyID := in.KeyID
	if keyID == "" {
		derived, err := keys.KeyID(in.PrivateKey.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		keyID = derived
	}

	requestNonce := in.Nonce
	if requestNonce == "" {
		generated, err := nonce.New()
		if err != nil {
			return nil, err
		}
		requestNonce = generated
	}
	if err := nonce.Validate(requestNonce); err != nil {
		return nil, err
	}

	requestID := in.RequestID
	if requestID == "" {
		generated, err := nonce.NewWithBytes(16)
		if err != nil {
			return nil, err
		}
		requestID = generated
	}

	traceParent := in.TraceParent
	if traceParent == "" {
		generated, err := NewTraceParent()
		if err != nil {
			return nil, err
		}
		traceParent = generated
	}

	created := in.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	body := in.Body
	hasBody := len(body) > 0

	if hasBody && isJSONContentType(in.Request.Header.Get(protocol.HTTPName(protocol.HeaderContentType))) {
		canonical, err := jcs.Canonicalize(body)
		if err != nil {
			return nil, err
		}
		body = canonical
	}

	// Identity headers must be set before the base is built: they are
	// covered components.
	h := in.Request.Header
	h.Set(protocol.HTTPName(protocol.HeaderTenantID), in.TenantID)
	h.Set(protocol.HTTPName(protocol.HeaderAgentID), in.AgentID)
	h.Set(protocol.HTTPName(protocol.HeaderRequestID), requestID)
	h.Set(protocol.HTTPName(protocol.HeaderSignatureVersion), protocol.SignatureVersion)
	h.Set(protocol.HTTPName(protocol.HeaderTraceParent), traceParent)

	contentDigest := ""
	if hasBody {
		contentDigest = digest.Compute(body)
		h.Set(protocol.HTTPName(protocol.HeaderContentDigest), contentDigest)
		if h.Get(protocol.HTTPName(protocol.HeaderContentType)) == "" {
			h.Set(protocol.HTTPName(protocol.HeaderContentType), "application/json")
		}
	}

	SetRequestBody(in.Request, body)

	canonReq, err := canonicalhttp.FromHTTPRequest(in.Request, body)
	if err != nil {
		return nil, err
	}

	components := protocol.CoveredComponents(hasBody)
	params := canonicalhttp.SignatureParams{
		Created: created.Unix(),
		KeyID:   keyID,
		Nonce:   requestNonce,
		Tag:     protocol.SignatureTag,
	}

	base, err := canonicalhttp.BuildSignatureBase(canonReq, components, params)
	if err != nil {
		return nil, err
	}

	signature, err := keys.Sign(in.PrivateKey, base)
	if err != nil {
		return nil, err
	}

	label := in.Label
	if label == "" {
		label = protocol.DefaultSignatureLabel
	}

	signatureInput, err := BuildSignatureInput(label, components, params)
	if err != nil {
		return nil, err
	}
	signatureHeader := BuildSignatureHeader(label, signature)

	h.Set(protocol.HTTPName(protocol.HeaderSignatureInput), signatureInput)
	h.Set(protocol.HTTPName(protocol.HeaderSignature), signatureHeader)

	return &SignResult{
		SignatureInput: signatureInput,
		Signature:      signatureHeader,
		SignatureBase:  base,
		ContentDigest:  contentDigest,
		KeyID:          keyID,
		Nonce:          requestNonce,
		RequestID:      requestID,
		Created:        params.Created,
		Body:           body,
	}, nil
}
