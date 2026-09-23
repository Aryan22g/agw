"""Deterministic request canonicalization and signature-base construction.

Everything here is byte-exact by design. If a signer and a verifier disagree
about a single space the signature fails; if they agree about the wrong bytes
the signature proves nothing.
"""

from urllib.parse import urlsplit

from . import digest as digest_mod
from . import protocol
from .errors import CanonicalizationError


class CanonicalRequest:
    """The normalized view of a request that the signature base is built from."""

    def __init__(self, method, authority, path, query, headers, body=None):
        self.method = method.upper().strip()
        self.authority = authority.lower().strip()
        self.path = path
        self.query = query
        # Header names are lowercased; values are single-valued and stripped.
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body or b""

    @property
    def has_body(self) -> bool:
        return len(self.body) > 0

    @classmethod
    def from_url(cls, method, url, headers, body=None):
        parts = urlsplit(url)
        return cls(
            method=method,
            authority=parts.netloc,
            path=parts.path or "/",
            query=canonical_query(parts.query),
            headers=headers,
            body=body,
        )


def canonical_query(raw: str) -> str:
    """Render a raw query string in AGS1 form.

    An absent query signs as ``?`` rather than as the empty string. Without a
    distinct marker, "no query" and "empty query" would produce the same
    signature base, letting a request signed with neither be replayed with an
    empty one appended.

    The query is never parsed and re-emitted: a verifier that re-sorted
    parameters would accept a reordered query as equivalent, letting an
    attacker change parameter precedence downstream while the signature stayed
    valid.
    """
    raw = raw[1:] if raw.startswith("?") else raw
    return "?" + raw if raw else "?"


def validate_covered_components(components, has_body: bool) -> None:
    """Check a declared component list against the AGS1 profile.

    The list is not taken on trust: it must match the profile exactly, in
    order. Accepting an arbitrary subset would let a signer omit, say, @path or
    content-digest and still produce a signature a verifier accepts -- meaning
    the signature covers less than the verifier believes.
    """
    required = protocol.covered_components(has_body)

    if len(components) != len(required):
        shape = "body-bearing" if has_body else "body-less"
        raise CanonicalizationError(
            f"got {len(components)} covered components, AGS1 requires "
            f"{len(required)} for a {shape} request"
        )

    seen = set()
    for index, component in enumerate(components):
        if component in seen:
            raise CanonicalizationError(f"duplicate covered component: {component!r}")
        seen.add(component)

        if not protocol.is_supported_component(component):
            raise CanonicalizationError(f"unsupported covered component: {component!r}")
        if component != required[index]:
            raise CanonicalizationError(
                f"covered component at position {index} is {component!r}, "
                f"AGS1 requires {required[index]!r}"
            )


def resolve_component_value(request: CanonicalRequest, component: str) -> str:
    if component == protocol.COMPONENT_METHOD:
        return request.method
    if component == protocol.COMPONENT_AUTHORITY:
        return request.authority
    if component == protocol.COMPONENT_PATH:
        return request.path
    if component == protocol.COMPONENT_QUERY:
        return request.query

    if not protocol.is_supported_component(component):
        raise CanonicalizationError(f"unsupported covered component: {component!r}")

    if component not in request.headers:
        raise CanonicalizationError(f"missing covered component: {component!r}")

    value = request.headers[component]
    if component == protocol.COMPONENT_CONTENT_DIGEST:
        return digest_mod.normalize(value)
    return value


def build_component_line(request: CanonicalRequest, component: str) -> str:
    value = resolve_component_value(request, component)
    if protocol.requires_strict_serialization(component):
        return '"%s";%s: %s' % (component, protocol.PARAM_STRICT_SERIALIZATION, value)
    return '"%s": %s' % (component, value)


def build_signature_params_line(components, created, key_id, nonce, tag) -> str:
    """Render the trailing @signature-params line.

    It MUST be last, and its component list MUST match the lines above it. That
    is what binds the signature to the specific set of components covered:
    without it, an attacker could strip a component line and present the
    shorter base as the original.
    """
    quoted = []
    for component in components:
        if protocol.requires_strict_serialization(component):
            quoted.append('"%s";%s' % (component, protocol.PARAM_STRICT_SERIALIZATION))
        else:
            quoted.append('"%s"' % component)

    return '"@signature-params": (%s);created=%d;keyid="%s";nonce="%s";tag="%s"' % (
        " ".join(quoted), created, key_id, nonce, tag,
    )


def build_signature_base(request: CanonicalRequest, components, created, key_id, nonce, tag) -> bytes:
    """Construct the exact bytes that are signed and verified."""
    validate_covered_components(components, request.has_body)

    lines = [build_component_line(request, c) for c in components]
    lines.append(build_signature_params_line(components, created, key_id, nonce, tag))
    return "\n".join(lines).encode("utf-8")
