"""RFC 8785 JSON Canonicalization Scheme.

AGS1 signs the exact transmitted bytes. For JSON bodies those bytes MUST be JCS
output, so that an agent in Python and an agent in Go signing the same logical
payload produce byte-identical input to the digest.

This is a self-contained implementation rather than a dependency, because the
canonical form is a wire contract: the conformance corpus pins the exact bytes,
and a third-party library changing its serialization in a patch release would
silently break every signature.
"""

import json
import math
import re

from .errors import CanonicalizationError


def canonicalize(value) -> bytes:
    """Return the RFC 8785 canonical form of a JSON-compatible value."""
    return _serialize(value).encode("utf-8")


def canonicalize_bytes(raw: bytes) -> bytes:
    """Parse JSON bytes and return their canonical form.

    Duplicate object keys are rejected rather than resolved. They are ambiguous
    across parsers -- one implementation keeps the first value, another the last
    -- so a signer and verifier could canonicalize the same bytes differently.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalizationError(f"body is not valid UTF-8: {exc}") from exc

    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(f"invalid JSON body: {exc}") from exc

    return canonicalize(value)


def _reject_duplicate_keys(pairs):
    seen = {}
    for key, val in pairs:
        if key in seen:
            raise CanonicalizationError(f"duplicate JSON object key: {key!r}")
        seen[key] = val
    return seen


def _serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, (int, float)):
        return _serialize_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        # RFC 8785 orders members by the UTF-16 code units of their keys, which
        # is what Python's default string ordering gives for the BMP. Keys are
        # sorted on their UTF-16 encoding to stay correct above it too.
        items = sorted(value.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        return "{" + ",".join(
            _serialize_string(k) + ":" + _serialize(v) for k, v in items
        ) + "}"

    raise CanonicalizationError(f"value of type {type(value).__name__} is not JSON")


def _utf16_sort_key(key: str):
    if not isinstance(key, str):
        raise CanonicalizationError("JSON object keys must be strings")
    return key.encode("utf-16-be")


def _serialize_number(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, int):
        return str(value)

    if math.isnan(value) or math.isinf(value):
        # NaN and Infinity have no JSON representation, so a payload
        # containing them cannot be signed deterministically.
        raise CanonicalizationError("NaN and Infinity are not representable in JSON")

    if value == int(value) and abs(value) < 1e21:
        return str(int(value))

    # ES6 Number::toString, which RFC 8785 specifies, is what repr() produces
    # for a double in Python: the shortest representation that round-trips.
    text = repr(float(value))
    return _to_es6_exponent(text)


_EXP_RE = re.compile(r"^(-?)(\d+)(?:\.(\d+))?e([+-])(\d+)$")


def _to_es6_exponent(text: str) -> str:
    """Convert Python's exponent spelling to the ECMAScript form JCS requires."""
    match = _EXP_RE.match(text)
    if not match:
        return text

    sign, int_part, frac_part, exp_sign, exp_digits = match.groups()
    mantissa = int_part + ("." + frac_part if frac_part else "")
    return f"{sign}{mantissa}e{exp_sign}{int(exp_digits)}"


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _serialize_string(value: str) -> str:
    """Serialize a string per RFC 8785.

    Unicode is preserved exactly: no NFC or NFKC normalization is applied,
    because normalizing would change the transmitted bytes out from under the
    digest the sender computed. Only the control range and the two mandatory
    escapes are escaped.
    """
    out = ['"']
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
