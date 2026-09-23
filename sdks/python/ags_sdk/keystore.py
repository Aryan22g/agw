"""Local keystore, interoperable with the ``ags`` CLI."""

import json
import os
import stat

from .errors import AGS1Error
from . import keys as keys_mod


def default_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".ags", "credentials.json")


def load_keystore(path=None) -> dict:
    """Load a keystore written by the ``ags`` CLI or by save_keystore.

    Refuses a file readable by other users. A key already exposed to other
    local accounts should be rotated, not used, so this is an error rather than
    a warning.
    """
    path = path or default_path()

    if not os.path.exists(path):
        raise AGS1Error(f"no keystore at {path}")

    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        raise AGS1Error(
            f"{path} is readable by other users (mode {mode:04o}); "
            f"run 'chmod 600 {path}' and rotate this key, since it may already be compromised"
        )

    with open(path, "r", encoding="utf-8") as handle:
        record = json.load(handle)

    private_key = keys_mod.load_private_key(record["privateKey"])

    # The stored kid must still match the stored key material, so a hand-edited
    # file cannot point the SDK at a credential it does not hold the key for.
    derived = keys_mod.key_id(private_key.public_key())
    declared = record.get("keyId")
    if declared and declared != derived:
        raise AGS1Error(
            f"keystore key id {declared!r} does not match the stored key material ({derived!r})"
        )
    record["keyId"] = derived
    record["_private_key"] = private_key

    return record


def save_keystore(path, tenant_id, agent_id, private_key, gateway_url=None) -> str:
    """Write a keystore with 0600 permissions.

    The write goes to a temporary file in the same directory and is then
    renamed, so an interrupted write cannot leave a truncated key file behind.
    """
    import base64
    import tempfile
    from datetime import datetime, timezone

    path = path or default_path()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)

    public_key = private_key.public_key()
    record = {
        "tenantId": tenant_id,
        "agentId": agent_id,
        "keyId": keys_mod.key_id(public_key),
        "privateKey": base64.b64encode(keys_mod.private_key_bytes(private_key)).decode("ascii"),
        "publicKey": base64.b64encode(keys_mod.public_key_bytes(public_key)).decode("ascii"),
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }
    if gateway_url:
        record["gatewayUrl"] = gateway_url

    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".credentials-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    return path
