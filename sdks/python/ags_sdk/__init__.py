"""AGS1 Python SDK.

Minimal integration::

    from ags_sdk import Client

    client = Client(
        gateway_url="https://gw.example.com",
        tenant_id="tenant-alpha",
        agent_id="agent-support",
        private_key=private_key,
    )
    response = client.post_json("/v1/tools/github/repos/acme/app/issues",
                                {"title": "Filed by an agent"})

Signing, canonicalization, digests and nonces are handled for you; the wire
profile is defined in RFC-0002 and pinned by the shared conformance corpus.
"""

from .client import Client
from .errors import (
    AGS1Error,
    CanonicalizationError,
    GatewayError,
    SigningError,
    REASON_CREDENTIAL_EXPIRED,
    REASON_CREDENTIAL_REVOKED,
    REASON_DIGEST_MISMATCH,
    REASON_POLICY_DENIED,
    REASON_PRINCIPAL_NOT_FOUND,
    REASON_RATE_LIMITED,
    REASON_REPLAY_DETECTED,
    REASON_REQUEST_EXPIRED,
    REASON_ROUTE_UNKNOWN,
    REASON_SIGNATURE_INVALID,
    REASON_SIGNATURE_MALFORMED,
)
from .keystore import load_keystore, save_keystore
from .proof import registration_payload, sign_proof, verify_proof
from .signer import sign_request, verify_request

__all__ = [
    "Client",
    "AGS1Error",
    "CanonicalizationError",
    "GatewayError",
    "SigningError",
    "sign_request",
    "verify_request",
    "load_keystore",
    "save_keystore",
    "registration_payload",
    "sign_proof",
    "verify_proof",
    "REASON_POLICY_DENIED",
    "REASON_REPLAY_DETECTED",
    "REASON_RATE_LIMITED",
    "REASON_CREDENTIAL_REVOKED",
    "REASON_CREDENTIAL_EXPIRED",
    "REASON_SIGNATURE_INVALID",
    "REASON_SIGNATURE_MALFORMED",
    "REASON_DIGEST_MISMATCH",
    "REASON_REQUEST_EXPIRED",
    "REASON_PRINCIPAL_NOT_FOUND",
    "REASON_ROUTE_UNKNOWN",
]

__version__ = "1.0.0"
