"""Proof of possession for credential registration.

Mirrors ``pkg/ags1/keys/proof.go``. The registrant demonstrates it holds the
private key matching the public key it submits; without this, a public key the
registrant does not control can be registered, producing a credential nobody
can act as -- or one an attacker supplied.
"""

import base64
import time

from . import keys as keys_mod
from .errors import AGS1Error

# Binds a proof to what it is for, so a proof minted for one operation cannot
# be presented for another.
PURPOSE = "ags1-credential-registration-v1"

# How long a registration proof stays acceptable.
MAX_AGE_SECONDS = 300


def proof_input(tenant_id: str, agent_id: str, key_id: str, issued_at: int) -> bytes:
    """Build the exact bytes a registration proof signs.

    Length-prefixed rather than delimiter-joined: an identifier containing the
    delimiter could otherwise shift field boundaries so a proof for one tenant
    reads as a proof for another.

    The key id is included, so a proof is inseparable from the key it
    registers -- which is what makes replaying a captured proof useless.
    """
    out = PURPOSE + "\n"
    for field in (tenant_id, agent_id, key_id, str(int(issued_at))):
        out += f"{len(field)}:{field}"
    return out.encode("utf-8")


def sign_proof(private_key, tenant_id: str, agent_id: str, key_id: str, issued_at=None):
    """Return ``(proof, issued_at)`` for a credential registration."""
    if issued_at is None:
        issued_at = int(time.time())
    issued_at = int(issued_at)

    signature = private_key.sign(proof_input(tenant_id, agent_id, key_id, issued_at))
    return base64.b64encode(signature).decode("ascii"), issued_at


def verify_proof(public_key, tenant_id, agent_id, key_id, proof, issued_at, now=None):
    """Verify a registration proof. Raises AGS1Error on any failure."""
    now = int(now if now is not None else time.time())
    issued_at = int(issued_at)

    if now - issued_at > MAX_AGE_SECONDS:
        raise AGS1Error(
            f"proof of possession: issued {now - issued_at}s ago, limit is {MAX_AGE_SECONDS}s"
        )
    if issued_at > now + MAX_AGE_SECONDS:
        raise AGS1Error("proof of possession: issuedAt is too far in the future")

    derived = keys_mod.key_id(public_key)
    if derived != key_id:
        raise AGS1Error(
            f"registration names {key_id!r} but the submitted key is {derived!r}"
        )

    try:
        raw = base64.b64decode(proof, validate=True)
    except Exception as exc:
        raise AGS1Error(f"proof of possession: not valid base64: {exc}") from exc

    keys_mod.verify(public_key, proof_input(tenant_id, agent_id, key_id, issued_at), raw)


def registration_payload(tenant_id, agent_id, private_key, public_key=None, expires_at=None):
    """Build a complete credential registration body, proof included.

    Callers should use this rather than assembling the JSON by hand: a
    registration flow that makes the operator construct a signature manually is
    one they will be tempted to disable.
    """
    if public_key is None:
        public_key = private_key.public_key()

    key_id = keys_mod.key_id(public_key)
    proof, issued_at = sign_proof(private_key, tenant_id, agent_id, key_id)

    payload = {
        "tenantId": tenant_id,
        "agentId": agent_id,
        "keyId": key_id,
        "algorithm": "Ed25519",
        "publicKey": base64.b64encode(keys_mod.public_key_bytes(public_key)).decode("ascii"),
        "proof": proof,
        "proofIssuedAt": issued_at,
    }
    if expires_at is not None:
        payload["expiresAt"] = expires_at

    return payload
