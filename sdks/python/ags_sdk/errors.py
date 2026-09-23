"""AGS1 SDK error types."""


class AGS1Error(Exception):
    """Base class for every SDK error."""


class SigningError(AGS1Error):
    """Raised when a request cannot be signed."""


class CanonicalizationError(AGS1Error):
    """Raised when a body or request cannot be canonicalized deterministically."""


class GatewayError(AGS1Error):
    """A structured denial returned by the gateway.

    Branch on ``reason`` rather than ``status``: the reason code is a stable
    contract, while several distinct reasons deliberately share a status so the
    gateway does not reveal which one applied.
    """

    def __init__(self, status, reason, title=None, decision_id=None):
        self.status = status
        self.reason = reason
        self.title = title
        self.decision_id = decision_id

        detail = f"gateway returned {status} {reason}"
        if decision_id:
            detail += f" (decision {decision_id})"
        super().__init__(detail)

    @property
    def retryable(self) -> bool:
        """Whether retrying the same logical call could succeed.

        A replayed nonce is retryable because the SDK mints a fresh nonce per
        attempt, making a retry a genuinely new request. A policy denial is not:
        retrying only reproduces the denial and burns rate-limit budget.
        """
        if self.reason in (REASON_REPLAY_DETECTED, REASON_RATE_LIMITED):
            return True
        return self.status >= 500

    @property
    def is_revoked(self) -> bool:
        """Whether the credential is finished and the agent should re-register."""
        return self.reason in (REASON_CREDENTIAL_REVOKED, REASON_CREDENTIAL_EXPIRED)


# Reason codes, mirroring internal/gateway/decision.
REASON_SIGNATURE_INVALID = "signature_invalid"
REASON_SIGNATURE_MALFORMED = "signature_malformed"
REASON_DIGEST_MISMATCH = "digest_mismatch"
REASON_REQUEST_EXPIRED = "request_expired"
REASON_PRINCIPAL_NOT_FOUND = "principal_not_found"
REASON_CREDENTIAL_REVOKED = "credential_revoked"
REASON_CREDENTIAL_EXPIRED = "credential_expired"
REASON_REPLAY_DETECTED = "replay_detected"
REASON_POLICY_DENIED = "policy_denied"
REASON_RATE_LIMITED = "rate_limited"
REASON_ROUTE_UNKNOWN = "route_unknown"
