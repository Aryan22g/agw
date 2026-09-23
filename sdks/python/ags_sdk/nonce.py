"""AGS1 replay-protection nonces."""

import base64
import hashlib
import secrets

from . import protocol
from .errors import AGS1Error

# 32 bytes encodes to 43 base64url characters: comfortably above the 128-bit
# floor and inside the 22-64 character range the profile permits.
DEFAULT_BYTES = 32

_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def new(num_bytes: int = DEFAULT_BYTES) -> str:
    if num_bytes < protocol.NONCE_MIN_BYTES:
        raise AGS1Error(
            f"nonce entropy {num_bytes} bytes is below the {protocol.NONCE_MIN_BYTES}-byte minimum"
        )
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def validate(value: str) -> None:
    """Check a nonce against the AGS1 charset and length rules.

    A nonce becomes part of a replay-store key, so bounding its length and
    charset keeps key construction predictable and stops a caller burning
    replay-store capacity with oversized values.
    """
    if len(value) < protocol.NONCE_MIN_CHARS:
        raise AGS1Error(
            f"nonce is {len(value)} characters, minimum is {protocol.NONCE_MIN_CHARS}"
        )
    if len(value) > protocol.NONCE_MAX_CHARS:
        raise AGS1Error(
            f"nonce is {len(value)} characters, maximum is {protocol.NONCE_MAX_CHARS}"
        )
    for ch in value:
        if ch not in _ALPHABET:
            raise AGS1Error(f"nonce contains a character outside base64url: {ch!r}")


def hashed(value: str) -> str:
    """Return the base64url-nopad SHA-256 of a nonce."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(value.encode("utf-8")).digest()
    ).decode("ascii").rstrip("=")
