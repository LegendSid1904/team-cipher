"""Public-key store for the Sign/Verify flow.

Stores public keys under human-readable labels so the Verify step can
look up a signer's key automatically (no manual key upload on verify).

Persistence is optional via jsonbin.io (free tier), configured with:

  JSONBIN_KEYS_BIN_ID  -> a bin dedicated to the key registry
  JSONBIN_API_KEY      -> your secret access key (shared with events)

If unset, keys live in memory and reset on cold start (still fine for
an active demo session).
"""

import json
import os
import urllib.request

from datetime import datetime, timezone

KEYS_BIN_ID = os.environ.get("JSONBIN_KEYS_BIN_ID", "")
API_KEY = os.environ.get("JSONBIN_API_KEY", "")

BASE_URL = "https://api.jsonbin.io/v3/b"

# In-memory fallback: { label: {"public_key": pem, "created": iso, "name": str} }
_MEMORY = {}


def _configured() -> bool:
    return bool(KEYS_BIN_ID and API_KEY)


def _read() -> dict:
    if not _configured():
        return dict(_MEMORY)
    url = f"{BASE_URL}/{KEYS_BIN_ID}/latest"
    request = urllib.request.Request(url)
    request.add_header("X-Master-Key", API_KEY)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("record", {})
            if isinstance(data, dict):
                return data
            return dict(_MEMORY)
    except Exception:
        return dict(_MEMORY)


def _write(data: dict) -> bool:
    if not _configured():
        return False
    url = f"{BASE_URL}/{KEYS_BIN_ID}"
    request = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        method="PUT",
        headers={"Content-Type": "application/json", "X-Master-Key": API_KEY},
    )
    try:
        with urllib.request.urlopen(request, timeout=8):
            return True
    except Exception:
        return False


def register_public_key(label: str, public_key_pem: str, name: str = "") -> bool:
    label = _normalize(label)
    if not label:
        return False
    keys = _read()
    keys[label] = {
        "public_key": public_key_pem,
        "created": datetime.now(timezone.utc).isoformat(),
        "name": name,
    }
    if _write(keys):
        return True
    # fallback: keep in memory
    _MEMORY[label] = keys[label]
    return True


def get_public_key(label: str):
    """Return the stored key record for a label, or None."""
    label = _normalize(label)
    if not label:
        return None
    keys = _read()
    return keys.get(label)


def list_labels() -> list:
    keys = _read()
    out = []
    for label, record in keys.items():
        out.append(
            {
                "label": label,
                "name": record.get("name", ""),
                "created": record.get("created", ""),
                "key_size": _guess_key_size(record.get("public_key", "")),
            }
        )
    out.sort(key=lambda r: r.get("created", ""), reverse=True)
    return out


def _guess_key_size(pem: str) -> int:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        key = load_pem_public_key(pem.encode("utf-8"))
        k = getattr(key, "key_size", None)
        return int(k) if k else -1
    except Exception:
        return -1


def _normalize(label: str) -> str:
    label = (label or "").strip().lower()
    return label
