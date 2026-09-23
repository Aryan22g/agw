"""RFC 9530 Content-Digest handling for AGS1."""

import base64
import hashlib
import hmac

from .errors import CanonicalizationError

# AGS1 v1 supports exactly one digest algorithm. A verifier that accepts a
# caller-selected algorithm can be talked down to the weakest one it knows, so
# the set is closed rather than negotiated.
ALGORITHM = "sha-256"

_PREFIX = ALGORITHM + "=:"
_SUFFIX = ":"


def compute(body: bytes) -> str:
    """Return the Content-Digest header value for the exact transmitted bytes.

    For a JSON body that means the JCS output, not the pre-canonicalization
    source.
    """
    digest = hashlib.sha256(body).digest()
    return _PREFIX + base64.b64encode(digest).decode("ascii") + _SUFFIX


def parse(value: str) -> str:
    """Extract the base64 digest from a Content-Digest header value."""
    value = value.strip()
    if not value.startswith(_PREFIX) or not value.endswith(_SUFFIX):
        raise CanonicalizationError(
            f"malformed content-digest: expected sha-256=:<base64>: form, got {value!r}"
        )

    inner = value[len(_PREFIX):-len(_SUFFIX)]
    if not inner:
        raise CanonicalizationError("malformed content-digest: empty digest")

    try:
        base64.b64decode(inner, validate=True)
    except Exception as exc:
        raise CanonicalizationError(f"content-digest is not valid base64: {exc}") from exc

    return inner


def validate(body: bytes, provided: str) -> None:
    """Check a Content-Digest header against the body bytes.

    The comparison is constant-time. Digest comparison happens before signature
    verification, so a timing side channel here would leak information about
    the expected digest to an unauthenticated caller.
    """
    parse(provided)
    if not hmac.compare_digest(compute(body), provided.strip()):
        raise CanonicalizationError("content-digest does not match the body")


def normalize(value: str) -> str:
    """Re-serialize a Content-Digest into strict structured-field form.

    This is what the ``sf`` component parameter calls for. AGS1 permits exactly
    one algorithm and one member, so normalization reduces to validating the
    shape and emitting the canonical spelling, discarding whitespace an
    intermediary may have introduced.
    """
    return _PREFIX + parse(value) + _SUFFIX
