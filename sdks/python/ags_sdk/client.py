"""Signing HTTP client for the Agent Gateway."""

import json
from urllib.parse import urlsplit, urlunsplit

from . import protocol
from .errors import AGS1Error, GatewayError
from .signer import sign_request


class Client:
    """A signing HTTP client aimed at one gateway.

    Every request is signed with the agent's Ed25519 key. The caller never
    handles canonicalization, digests, nonces or signature bases.
    """

    def __init__(
        self,
        gateway_url,
        tenant_id,
        agent_id,
        private_key,
        key_id=None,
        timeout=30,
        session=None,
    ):
        if not gateway_url:
            raise AGS1Error("gateway url is required")

        parts = urlsplit(gateway_url.rstrip("/"))
        if not parts.scheme or not parts.netloc:
            raise AGS1Error(f"gateway url {gateway_url!r} must be absolute")

        # A signature proves who sent a request; it does not keep the body
        # private. Refusing plaintext by default stops an agent shipping
        # payloads in the clear without having made that choice deliberately.
        if parts.scheme != "https" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
            raise AGS1Error(
                f"gateway url must use https (got {parts.scheme!r}); "
                "plain http is permitted only for loopback during development"
            )

        if not tenant_id or not agent_id:
            raise AGS1Error("tenant id and agent id are required")

        self.base_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        self.tenant_id = tenant_id
        self.agent_id = agent_id
        self.private_key = private_key
        self.key_id = key_id
        self.timeout = timeout

        if session is None:
            import requests

            session = requests.Session()
        self.session = session

    def _resolve(self, path):
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path

    def request(self, method, path, body=None, headers=None, content_type=None):
        """Sign and send a request, returning the raw response."""
        url = self._resolve(path)

        raw_body = None
        if body is not None:
            if isinstance(body, (bytes, bytearray)):
                raw_body = bytes(body)
            elif isinstance(body, str):
                raw_body = body.encode("utf-8")
            else:
                raw_body = json.dumps(body).encode("utf-8")
                content_type = content_type or "application/json"

        signed_headers, signed_body, _ = sign_request(
            method=method,
            url=url,
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            private_key=self.private_key,
            body=raw_body,
            headers=headers,
            content_type=content_type,
            key_id=self.key_id,
        )

        return self.session.request(
            method=method,
            url=url,
            headers=signed_headers,
            data=signed_body if signed_body else None,
            timeout=self.timeout,
        )

    def get(self, path, headers=None):
        return self.request("GET", path, headers=headers)

    def delete(self, path, headers=None):
        return self.request("DELETE", path, headers=headers)

    def post_json(self, path, payload, headers=None):
        return self.request("POST", path, body=payload, headers=headers,
                            content_type="application/json")

    def put_json(self, path, payload, headers=None):
        return self.request("PUT", path, body=payload, headers=headers,
                            content_type="application/json")

    @staticmethod
    def decode(response):
        """Return the decoded JSON body, raising GatewayError on a denial.

        Denials become a typed error carrying the stable reason code and the
        decision id, so callers branch on meaning rather than on status.
        """
        if response.status_code >= 400:
            raise _gateway_error(response)

        if not response.content:
            return None
        return response.json()


def _gateway_error(response) -> GatewayError:
    try:
        payload = response.json()
    except Exception:
        payload = {}

    reason = payload.get("reason")
    if not reason:
        # A non-JSON error body means something other than the gateway
        # answered -- a proxy or load balancer. Surface the status rather than
        # inventing a reason code.
        reason = "unknown"

    return GatewayError(
        status=response.status_code,
        reason=reason,
        title=payload.get("title"),
        decision_id=payload.get("decisionId"),
    )
