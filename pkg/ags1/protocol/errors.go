package protocol

import "errors"

// AGS1 protocol errors.
//
// These are sentinel values so callers can branch with errors.Is instead of
// matching on message text. The gateway maps them to HTTP statuses and audit
// reasons; string matching for that purpose is a bug, not a shortcut.
var (
	// Structural / parsing.
	ErrNilRequest              = errors.New("ags1: nil canonical request")
	ErrNilSignatureInput       = errors.New("ags1: nil signature input")
	ErrMalformedSignatureInput = errors.New("ags1: malformed signature-input")
	ErrMalformedSignature      = errors.New("ags1: malformed signature header")
	ErrUnsupportedComponent    = errors.New("ags1: unsupported covered component")
	ErrMissingCoveredComponent = errors.New("ags1: missing covered component")
	ErrDuplicateComponent      = errors.New("ags1: duplicate covered component")
	ErrComponentSetMismatch    = errors.New("ags1: covered components do not match the AGS1 profile")
	ErrMissingStrictParam      = errors.New("ags1: component requires the sf parameter")

	// Signature parameters.
	ErrMissingCreated        = errors.New("ags1: missing created parameter")
	ErrMissingKeyID          = errors.New("ags1: missing keyid parameter")
	ErrMissingNonce          = errors.New("ags1: missing nonce parameter")
	ErrMissingTag            = errors.New("ags1: missing tag parameter")
	ErrInvalidTag            = errors.New("ags1: signature tag does not match this profile")
	ErrForbiddenParameter    = errors.New("ags1: forbidden signature parameter")
	ErrDuplicateParameter    = errors.New("ags1: duplicate signature parameter")
	ErrAlgorithmNotOnTheWire = errors.New("ags1: alg parameter is forbidden; algorithm comes from the credential")

	// Headers.
	ErrMissingRequiredHeader = errors.New("ags1: missing required header")
	ErrDuplicateHeader       = errors.New("ags1: duplicate required header")

	// Body / digest.
	ErrInvalidJSON           = errors.New("ags1: invalid JSON body")
	ErrInvalidUTF8           = errors.New("ags1: body is not valid UTF-8")
	ErrDuplicateJSONKey      = errors.New("ags1: duplicate JSON object key")
	ErrNonFiniteNumber       = errors.New("ags1: NaN and Infinity are not representable")
	ErrInvalidContentDigest  = errors.New("ags1: malformed content-digest")
	ErrContentDigestMismatch = errors.New("ags1: content-digest does not match body")

	// Timestamps and nonce.
	ErrRequestExpired     = errors.New("ags1: request is outside the acceptance window")
	ErrRequestNotYetValid = errors.New("ags1: request created beyond the permitted clock skew")
	ErrNonceTooShort      = errors.New("ags1: nonce entropy below the required minimum")
	ErrNonceTooLong       = errors.New("ags1: nonce exceeds the permitted length")
	ErrNonceCharset       = errors.New("ags1: nonce contains characters outside base64url")

	// Keys.
	ErrUnsupportedAlgorithm = errors.New("ags1: unsupported algorithm")
	ErrInvalidPublicKey     = errors.New("ags1: invalid Ed25519 public key")
	ErrInvalidPrivateKey    = errors.New("ags1: invalid Ed25519 private key")
	ErrInvalidJWK           = errors.New("ags1: invalid JWK")
	ErrKeyIDMismatch        = errors.New("ags1: keyid does not match the JWK thumbprint")

	// Verification.
	ErrSignatureInvalid = errors.New("ags1: signature verification failed")
)
