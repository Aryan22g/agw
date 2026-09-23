"""AGS1 request signing and verification."""

import base64
import secrets
import time

from . import canonical, digest as digest_mod, jcs, keys as keys_mod, nonce as nonce_mod, protocol
from .errors import AGS1Error, SigningError


def build_signature_input(label, components, created, key_id, nonce_value, tag) -> str:
    quoted = []
    for component in components:
        if protocol.requires_strict_serialization(component):
            quoted.append('"%s";%s' % (component, protocol.PARAM_STRICT_SERIALIZATION))
        else:
            quoted.append('"%s"' % component)

    return '%s=(%s);created=%d;keyid="%s";nonce="%s";tag="%s"' % (
        label, " ".join(quoted), created, key_id, nonce_value, tag,
    )


def build_signature_header(label: str, signature: bytes) -> str:
    """Render the Signature header as an RFC 9421 byte sequence."""
    return "%s=:%s:" % (label, base64.b64encode(signature).decode("ascii"))


def new_traceparent() -> str:
    """Generate a W3C traceparent.

    AGS1 signs traceparent so the trace identity a request claims cannot be
    swapped after signing, which is what makes the audit trail joinable to
    distributed traces without trusting the caller.
    """
    return "00-%s-%s-01" % (secrets.token_hex(16), secrets.token_hex(8))


def is_json_content_type(content_type: str) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    return ct == "application/json" or ct.endswith("+json")


def sign_request(
    method,
    url,
    tenant_id,
    agent_id,
    private_key,
    body=None,
    headers=None,
    content_type=None,
    key_id=None,
    nonce_value=None,
    request_id=None,
    traceparent=None,
    created=None,
    label=protocol.DEFAULT_SIGNATURE_LABEL,
):
    """Sign a request, returning ``(headers, body)`` ready to send.

    Order matters: the body is canonicalized first, then digested, then the
    digest header is set, and only then is the signature base built -- because
    the base covers the digest header. Computing the digest over
    pre-canonicalization bytes is the classic way to produce a signature that
    verifies nowhere.
    """
    if not tenant_id or not agent_id:
        raise SigningError("tenant id and agent id are required")

    out_headers = dict(headers or {})

    if key_id is None:
        key_id = keys_mod.key_id(private_key.public_key())

    if nonce_value is None:
        nonce_value = nonce_mod.new()
    nonce_mod.validate(nonce_value)

    if request_id is None:
        request_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
    if traceparent is None:
        traceparent = new_traceparent()
    if created is None:
        created = int(time.time())

    body_bytes = body if body is not None else b""
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode("utf-8")

    has_body = len(body_bytes) > 0

    if has_body:
        ct = content_type or out_headers.get(protocol.HEADER_CONTENT_TYPE) or "application/json"
        if is_json_content_type(ct):
            body_bytes = jcs.canonicalize_bytes(body_bytes)
        out_headers[protocol.HEADER_CONTENT_TYPE] = ct

    # Identity headers must be set before the base is built: they are covered
    # components.
    out_headers[protocol.HEADER_TENANT_ID] = tenant_id
    out_headers[protocol.HEADER_AGENT_ID] = agent_id
    out_headers[protocol.HEADER_REQUEST_ID] = request_id
    out_headers[protocol.HEADER_SIGNATURE_VERSION] = protocol.SIGNATURE_VERSION
    out_headers[protocol.HEADER_TRACEPARENT] = traceparent

    if has_body:
        out_headers[protocol.HEADER_CONTENT_DIGEST] = digest_mod.compute(body_bytes)

    request = canonical.CanonicalRequest.from_url(method, url, out_headers, body_bytes)
    components = protocol.covered_components(has_body)

    base = canonical.build_signature_base(
        request, components, created, key_id, nonce_value, protocol.SIGNATURE_TAG
    )

    signature = keys_mod.sign(private_key, base)

    out_headers[protocol.HEADER_SIGNATURE_INPUT] = build_signature_input(
        label, components, created, key_id, nonce_value, protocol.SIGNATURE_TAG
    )
    out_headers[protocol.HEADER_SIGNATURE] = build_signature_header(label, signature)

    return out_headers, body_bytes, {
        "signature_base": base,
        "key_id": key_id,
        "nonce": nonce_value,
        "request_id": request_id,
        "created": created,
    }


def verify_request(method, url, headers, body, public_key, now=None):
    """Verify a signed request. Raises on any failure, returns metadata on success.

    This is Stage-1 work only: it answers whether these exact bytes were signed
    by the private key matching this public key, recently, under this profile.
    It knows nothing about tenants, revocation or authorization.
    """
    from .parser import parse_signature_input, parse_signature_header, match_label

    lowered = {k.lower(): v for k, v in headers.items()}
    sig_input_raw = lowered.get("signature-input")
    sig_raw = lowered.get("signature")
    if not sig_input_raw or not sig_raw:
        raise AGS1Error("missing Signature or Signature-Input header")

    parsed = parse_signature_input(sig_input_raw)
    sig_label, signature = parse_signature_header(sig_raw)
    match_label(parsed["label"], sig_label)

    body_bytes = body or b""
    request = canonical.CanonicalRequest.from_url(method, url, headers, body_bytes)

    canonical.validate_covered_components(parsed["components"], request.has_body)

    now = int(now if now is not None else time.time())
    created = parsed["created"]
    if created > now + protocol.MAX_CLOCK_SKEW_SECONDS:
        raise AGS1Error("request created beyond the permitted clock skew")
    if now - created > protocol.MAX_REQUEST_AGE_SECONDS:
        raise AGS1Error("request is outside the acceptance window")

    if request.has_body:
        provided = request.headers.get(protocol.COMPONENT_CONTENT_DIGEST)
        if not provided:
            raise AGS1Error("missing content-digest on a body-bearing request")
        digest_mod.validate(body_bytes, provided)

    base = canonical.build_signature_base(
        request, parsed["components"], created,
        parsed["keyid"], parsed["nonce"], parsed["tag"],
    )

    keys_mod.verify(public_key, base, signature)

    return {
        "key_id": parsed["keyid"],
        "nonce": parsed["nonce"],
        "created": created,
        "components": parsed["components"],
        "signature_base": base,
    }
