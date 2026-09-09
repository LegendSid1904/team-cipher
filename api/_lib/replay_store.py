"""Persistent replay-detection store backed by jsonbin.io.

Stores the SHA-256 fingerprints of processed documents so that
submitting an identical document again is flagged as a replay attack,
even after a Vercel cold start.

Configuration (env vars):
  JSONBIN_REPLAY_BIN_ID  -> bin id dedicated to the hash registry
  JSONBIN_API_KEY        -> your secret access key (shared)

If unset, fingerprints live in memory and reset on cold start.
"""

import json
import os
import urllib.request

BIN_ID = os.environ.get("JSONBIN_REPLAY_BIN_ID", "")
API_KEY = os.environ.get("JSONBIN_API_KEY", "")

BASE_URL = "https://api.jsonbin.io/v3/b"
MAX_HASHES = 500

# In-memory fallback: set of document hashes
_MEMORY_HASHES: set = set()


def _configured() -> bool:
    return bool(BIN_ID and API_KEY)


def _read_from_jsonbin() -> set:
    url = f"{BASE_URL}/{BIN_ID}/latest"
    request = urllib.request.Request(url)
    request.add_header("X-Master-Key", API_KEY)

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("record", {})
            if isinstance(data, dict):
                hashes = data.get("hashes", [])
                if isinstance(hashes, list):
                    return set(str(h) for h in hashes)
            return set()
    except Exception:
        return set()


def _write_to_jsonbin(hashes) -> bool:
    url = f"{BASE_URL}/{BIN_ID}"
    request = urllib.request.Request(
        url,
        data=json.dumps({"hashes": sorted(hashes)}).encode("utf-8"),
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "X-Master-Key": API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=8):
            return True
    except Exception:
        return False


def _load() -> set:
    if _configured():
        hashes = _read_from_jsonbin()
        if hashes:
            _MEMORY_HASHES.update(hashes)
    return _MEMORY_HASHES


def check_replay(document_hash: str) -> bool:
    """Return True if this document fingerprint is already known."""
    return document_hash in _load()


def record_document(document_hash: str) -> None:
    """Store a document fingerprint so a later copy is a replay."""
    hashes = _load()
    hashes.add(document_hash)
    hashes = set(sorted(hashes)[-MAX_HASHES:])

    _MEMORY_HASHES.clear()
    _MEMORY_HASHES.update(hashes)

    if _configured():
        _write_to_jsonbin(hashes)