"""AGS1 key handling: Ed25519 keypairs, JWK, and RFC 7638 thumbprints."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .errors import AGS1Error

KEY_TYPE_OKP = "OKP"
CURVE_ED25519 = "Ed25519"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def generate():
    """Generate a new Ed25519 keypair.

    Returns ``(private_key, public_key, key_id)``.
    """
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return private, public, key_id(public)


def public_key_bytes(public) -> bytes:
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(private) -> bytes:
    """Return the 64-byte form Go's ed25519 uses: seed || public key.

    Python's cryptography exposes only the 32-byte seed, while Go's
    ed25519.PrivateKey is 64 bytes. Emitting the Go layout keeps a keystore
    file readable by both SDKs, which matters because the CLI writes one and an
    agent in either language may read it.
    """
    seed = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return seed + public_key_bytes(private.public_key())


def load_private_key(raw) -> "ed25519.Ed25519PrivateKey":
    """Load a private key from raw bytes or a base64 string.

    Accepts both the 32-byte seed and the 64-byte Go layout, so a keystore
    written by the ``ags`` CLI loads without conversion.
    """
    if isinstance(raw, str):
        raw = base64.b64decode(raw)

    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise AGS1Error(
            f"invalid Ed25519 private key: {len(raw)} bytes, want 32 (seed) or 64 (seed||public)"
        )

    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(raw) -> "ed25519.Ed25519PublicKey":
    if isinstance(raw, str):
        raw = base64.b64decode(raw)
    if len(raw) != 32:
        raise AGS1Error(f"invalid Ed25519 public key: {len(raw)} bytes, want 32")
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def thumbprint_input(x: str) -> bytes:
    """Build the RFC 7638 canonical thumbprint input.

    RFC 7638 requires a JSON object containing only the REQUIRED members for
    the key type, lexicographically ordered, with no whitespace. For an OKP key
    those are exactly crv, kty and x -- already in lexicographic order.

    This is built by hand rather than with json.dumps on purpose: the
    thumbprint is a key identifier, so its byte-level stability across
    languages is the whole point. Every AGS1 SDK must produce these exact bytes.
    """
    return ('{"crv":"%s","kty":"%s","x":"%s"}' % (CURVE_ED25519, KEY_TYPE_OKP, x)).encode("utf-8")


def key_id(public) -> str:
    """Derive the AGS1 kid: the base64url-nopad RFC 7638 thumbprint."""
    x = _b64u(public_key_bytes(public))
    return _b64u(hashlib.sha256(thumbprint_input(x)).digest())


def public_key_to_jwk(public) -> dict:
    """Represent a public key as an AGS1 JWK, with its derived kid."""
    x = _b64u(public_key_bytes(public))
    return {
        "kty": KEY_TYPE_OKP,
        "crv": CURVE_ED25519,
        "x": x,
        "kid": _b64u(hashlib.sha256(thumbprint_input(x)).digest()),
        "use": "sig",
        "alg": "EdDSA",
    }


def jwk_to_public_key(jwk: dict):
    """Decode an AGS1 JWK, validating the key shape and any declared kid.

    The kid check matters: kid is the lookup key a verifier uses to find a
    credential, so a kid naming a key whose material hashes to something else
    could point a valid signature at the wrong credential.
    """
    if jwk.get("kty") != KEY_TYPE_OKP:
        raise AGS1Error(f"invalid JWK: kty must be {KEY_TYPE_OKP!r}, got {jwk.get('kty')!r}")
    if jwk.get("crv") != CURVE_ED25519:
        raise AGS1Error(f"invalid JWK: crv must be {CURVE_ED25519!r}, got {jwk.get('crv')!r}")

    x = jwk.get("x")
    if not x:
        raise AGS1Error("invalid JWK: missing x")

    padded = x + "=" * (-len(x) % 4)
    raw = base64.urlsafe_b64decode(padded)
    if len(raw) != 32:
        raise AGS1Error(f"invalid JWK: x decodes to {len(raw)} bytes, want 32")

    declared = jwk.get("kid")
    derived = _b64u(hashlib.sha256(thumbprint_input(x)).digest())
    if declared and declared != derived:
        raise AGS1Error(f"JWK kid {declared!r} does not match its key material ({derived!r})")

    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def sign(private, message: bytes) -> bytes:
    return private.sign(message)


def verify(public, message: bytes, signature: bytes) -> None:
    from cryptography.exceptions import InvalidSignature

    try:
        public.verify(signature, message)
    except InvalidSignature as exc:
        raise AGS1Error("signature verification failed") from exc
