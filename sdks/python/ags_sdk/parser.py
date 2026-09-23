"""Strict parsing of the AGS1 Signature-Input and Signature headers.

The parser is closed: it accepts exactly the four parameters AGS1 permits and
rejects everything else, including ``alg``. A tolerant parser would be a
downgrade vector, since anything it silently ignores is something the signer
believed it was communicating.
"""

import base64

from . import nonce as nonce_mod, protocol
from .errors import AGS1Error

_LABEL_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
)


def parse_signature_input(value: str) -> dict:
    value = (value or "").strip()
    if not value:
        raise AGS1Error("malformed signature-input: empty header")

    label, rest = _split_label(value)
    inner, params_raw = _split_inner_list(rest)
    components = _parse_components(inner)
    params = _parse_params(params_raw)

    if params["tag"] != protocol.SIGNATURE_TAG:
        raise AGS1Error(
            f"signature tag {params['tag']!r} does not match this profile "
            f"({protocol.SIGNATURE_TAG!r})"
        )

    # Nonce bounds are a profile constraint, enforced at parse time so a caller
    # reaching for the parser directly cannot skip the check.
    nonce_mod.validate(params["nonce"])

    return {
        "label": label,
        "components": components,
        "created": params["created"],
        "keyid": params["keyid"],
        "nonce": params["nonce"],
        "tag": params["tag"],
    }


def _split_label(value):
    index = value.find("=")
    if index <= 0:
        raise AGS1Error("malformed signature-input: missing label")

    label = value[:index].strip()
    if not label:
        raise AGS1Error("malformed signature-input: empty label")
    for ch in label:
        if ch not in _LABEL_CHARS:
            raise AGS1Error(f"malformed signature-input: invalid character {ch!r} in label")

    return label, value[index + 1:].strip()


def _split_inner_list(value):
    if not value.startswith("("):
        raise AGS1Error("malformed signature-input: expected '(' after label")
    close = value.find(")")
    if close < 0:
        raise AGS1Error("malformed signature-input: unterminated component list")
    return value[1:close], value[close + 1:].strip()


def _parse_components(inner):
    fields = inner.split()
    if not fields:
        raise AGS1Error("malformed signature-input: empty component list")

    components = []
    for field in fields:
        name, _, param = field.partition(";")

        if not (name.startswith('"') and name.endswith('"') and len(name) >= 3):
            raise AGS1Error(f"malformed signature-input: component {field!r} must be quoted")
        name = name[1:-1]

        if not protocol.is_supported_component(name):
            raise AGS1Error(f"unsupported covered component: {name!r}")

        if param == "":
            if protocol.requires_strict_serialization(name):
                raise AGS1Error(f"component {name!r} must carry ;sf")
        elif param == protocol.PARAM_STRICT_SERIALIZATION:
            if not protocol.requires_strict_serialization(name):
                raise AGS1Error(f"component {name!r} must not carry ;sf")
        else:
            raise AGS1Error(f"unknown component parameter {param!r} on {name!r}")

        components.append(name)

    return components


def _parse_params(value):
    if not value:
        raise AGS1Error("malformed signature-input: missing signature parameters")

    out = {}
    seen = set()

    for part in _split_params(value):
        key, _, raw = part.partition("=")
        key = key.strip()
        raw = raw.strip()

        if not _:
            raise AGS1Error(f"malformed signature-input: parameter {part!r} is not key=value")
        if key in seen:
            raise AGS1Error(f"duplicate signature parameter: {key!r}")
        seen.add(key)

        if key == "created":
            try:
                out["created"] = int(raw)
            except ValueError:
                raise AGS1Error(
                    f"malformed signature-input: created must be unix seconds, got {raw!r}"
                ) from None
        elif key in ("keyid", "nonce", "tag"):
            out[key] = _unquote(raw)
        elif key == "alg":
            raise AGS1Error(
                "alg is forbidden on the wire; the algorithm comes from the credential"
            )
        else:
            raise AGS1Error(f"forbidden signature parameter: {key!r}")

    for required in ("created", "keyid", "nonce", "tag"):
        if required not in out or out[required] in ("", None):
            raise AGS1Error(f"missing signature parameter: {required}")

    return out


def _split_params(value):
    """Split on ';' while ignoring separators inside quoted strings.

    Without this, a nonce or keyid containing ';' would break the parse.
    """
    parts = []
    current = []
    in_quote = False

    for ch in value:
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == ";" and not in_quote:
            token = "".join(current).strip()
            if token:
                parts.append(token)
            current = []
        else:
            current.append(ch)

    token = "".join(current).strip()
    if token:
        parts.append(token)
    return parts


def _unquote(value):
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def parse_signature_header(value: str):
    """Extract the label and raw signature bytes.

    The header is a structured-field dictionary whose value is a byte sequence
    delimited by colons -- NOT a bare base64 string. Feeding the whole header
    value to a base64 decoder is a real and easy mistake.
    """
    value = (value or "").strip()
    if not value:
        raise AGS1Error("malformed signature header: empty")

    index = value.find("=")
    if index <= 0:
        raise AGS1Error("malformed signature header: missing label")

    label = value[:index].strip()
    encoded = value[index + 1:].strip()

    if len(encoded) < 2 or not encoded.startswith(":") or not encoded.endswith(":"):
        raise AGS1Error("malformed signature header: must be a :base64: byte sequence")
    encoded = encoded[1:-1]
    if not encoded:
        raise AGS1Error("malformed signature header: empty signature")

    try:
        signature = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise AGS1Error(f"signature is not valid base64: {exc}") from exc

    return label, signature


def match_label(input_label, signature_label):
    """Check both headers refer to the same signature.

    Mismatched labels mean the two headers describe different signatures, so
    the parameters being validated would not be the ones actually signed.
    """
    if input_label != signature_label:
        raise AGS1Error(
            f"signature-input label {input_label!r} does not match "
            f"signature label {signature_label!r}"
        )
