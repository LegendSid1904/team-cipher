"""Optional JSON persistence for the security-event dashboard.

Uses jsonbin.io (free tier) to store recent events so the dashboard
survives cold starts. Configuration is provided via environment
variables set in Vercel:

  JSONBIN_BIN_ID   -> your bin id
  JSONBIN_API_KEY  -> your secret access key

If these are not set, the storage layer degrades gracefully and the
dashboard simply shows events collected during the current warm
instance (in-memory only). This keeps the demo working even without
extra setup.
"""

import json
import os
from typing import Optional

import urllib.request
import urllib.error

JSONBIN_BIN_ID = os.environ.get("JSONBIN_BIN_ID", "")
JSONBIN_API_KEY = os.environ.get("JSONBIN_API_KEY", "")

BASE_URL = "https://api.jsonbin.io/v3/b"

# In-memory fallback (reset on cold start)
_MEMORY_EVENTS: list = []

# Bounded at the source so we never grow without limit.
MAX_EVENTS = 50


def _configured() -> bool:
    return bool(JSONBIN_BIN_ID and JSONBIN_API_KEY)


def _read_from_jsonbin() -> list:
    url = f"{BASE_URL}/{JSONBIN_BIN_ID}/latest"
    request = urllib.request.Request(url)
    request.add_header("X-Master-Key", JSONBIN_API_KEY)

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("record", [])
            if isinstance(data, list):
                return data
            return []
    except Exception:
        return []


def _write_to_jsonbin(events: list) -> bool:
    url = f"{BASE_URL}/{JSONBIN_BIN_ID}"
    request = urllib.request.Request(
        url,
        data=json.dumps(events).encode("utf-8"),
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "X-Master-Key": JSONBIN_API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=8):
            return True
    except Exception:
        return False


def get_events() -> list:
    if _configured():
        events = _read_from_jsonbin()
        if events:
            return events[-MAX_EVENTS:]
    return list(_MEMORY_EVENTS)[-MAX_EVENTS:]


def add_event(event: dict) -> bool:
    event = dict(event)
    # newest first for display convenience
    events = get_events()
    events.insert(0, event)
    events = events[:MAX_EVENTS]

    if _configured():
        if _write_to_jsonbin(events):
            return True

    # fallback / no-config path: keep in memory, prepend digests
    _MEMORY_EVENTS.insert(0, event)
    del _MEMORY_EVENTS[MAX_EVENTS:]
    return True
