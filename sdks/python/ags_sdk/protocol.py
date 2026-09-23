"""Frozen AGS1 v1 wire constants.

This module is the Python mirror of ``pkg/ags1/protocol`` in the Go
implementation. Both derive from RFC-0002, and the conformance corpus at
``pkg/ags1/vectors/ags1-v1.json`` is what proves they agree: any drift between
them shows up as a failing vector rather than as a mysterious signature
rejection in production.

Changing any value here is a wire-breaking change and requires a new profile
version and tag, never an edit in place.
"""

PROFILE_NAME = "AGS1"
SIGNATURE_VERSION = "1"
SIGNATURE_TAG = "agw-sig-v1"
DEFAULT_SIGNATURE_LABEL = "sig1"
ALGORITHM_ED25519 = "Ed25519"

# Timestamp and replay policy (RFC-0002 sections 10-12).
MAX_REQUEST_AGE_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 60
ACCEPTANCE_WINDOW_SECONDS = MAX_REQUEST_AGE_SECONDS + MAX_CLOCK_SKEW_SECONDS
REPLAY_TTL_SECONDS = 900

NONCE_MIN_BYTES = 16
NONCE_MIN_CHARS = 22
NONCE_MAX_CHARS = 64

# Covered component identifiers, always lowercase.
COMPONENT_METHOD = "@method"
COMPONENT_AUTHORITY = "@authority"
COMPONENT_PATH = "@path"
COMPONENT_QUERY = "@query"
COMPONENT_CONTENT_DIGEST = "content-digest"
COMPONENT_CONTENT_TYPE = "content-type"
COMPONENT_AGENT_ID = "x-agent-id"
COMPONENT_TENANT_ID = "x-tenant-id"
COMPONENT_REQUEST_ID = "x-request-id"
COMPONENT_SIGNATURE_VERSION = "x-agent-signature-version"
COMPONENT_TRACEPARENT = "traceparent"

PARAM_STRICT_SERIALIZATION = "sf"

# AGS1 defines two closed component profiles rather than one list: 11
# components for a body-bearing request, 9 for a body-less one. RFC-0002
# section 1 fixed an 11-component list while section 3 made content-digest and
# content-type conditional on a body, which cannot both hold for a GET. What
# matters for security is that BOTH lists are closed sets, so a signer cannot
# shrink what its signature covers.
_COVERED_WITH_BODY = (
    COMPONENT_METHOD,
    COMPONENT_AUTHORITY,
    COMPONENT_PATH,
    COMPONENT_QUERY,
    COMPONENT_CONTENT_DIGEST,
    COMPONENT_CONTENT_TYPE,
    COMPONENT_AGENT_ID,
    COMPONENT_TENANT_ID,
    COMPONENT_REQUEST_ID,
    COMPONENT_SIGNATURE_VERSION,
    COMPONENT_TRACEPARENT,
)

_COVERED_WITHOUT_BODY = (
    COMPONENT_METHOD,
    COMPONENT_AUTHORITY,
    COMPONENT_PATH,
    COMPONENT_QUERY,
    COMPONENT_AGENT_ID,
    COMPONENT_TENANT_ID,
    COMPONENT_REQUEST_ID,
    COMPONENT_SIGNATURE_VERSION,
    COMPONENT_TRACEPARENT,
)

# Headers.
HEADER_AGENT_ID = "X-Agent-Id"
HEADER_TENANT_ID = "X-Tenant-Id"
HEADER_REQUEST_ID = "X-Request-Id"
HEADER_SIGNATURE_VERSION = "X-Agent-Signature-Version"
HEADER_TRACEPARENT = "Traceparent"
HEADER_CONTENT_TYPE = "Content-Type"
HEADER_CONTENT_DIGEST = "Content-Digest"
HEADER_SIGNATURE = "Signature"
HEADER_SIGNATURE_INPUT = "Signature-Input"


def covered_components(has_body: bool):
    """Return the required covered component list, in signing order."""
    return list(_COVERED_WITH_BODY if has_body else _COVERED_WITHOUT_BODY)


def requires_strict_serialization(component: str) -> bool:
    """Report whether a component must carry the ``sf`` parameter."""
    return component == COMPONENT_CONTENT_DIGEST


def is_supported_component(component: str) -> bool:
    return component in _COVERED_WITH_BODY
