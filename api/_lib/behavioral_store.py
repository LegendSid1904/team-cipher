"""Persistent behavioral-feature store backed by jsonbin.io.

Keeps a rolling log of verification events so that behavioral
features (verification frequency, source frequency, failed
verification rate, time-since-previous) survive Vercel cold starts.

Configuration (env vars):
  JSONBIN_BEHAVIOR_BIN_ID  -> bin id dedicated to the event log
  JSONBIN_API_KEY          -> your secret access key (shared)

If unset, behavior degrades to in-memory history (still fine for an
active warm instance / demo session).
"""

import json
import os
import urllib.request

from datetime import datetime, timezone

BIN_ID = os.environ.get("JSONBIN_BEHAVIOR_BIN_ID", "")
API_KEY = os.environ.get("JSONBIN_API_KEY", "")

BASE_URL = "https://api.jsonbin.io/v3/b"
MAX_EVENTS = 200

# In-memory fallback: [{ts, valid, source}]
_MEMORY_EVENTS: list = []


def _configured() -> bool:
    return bool(BIN_ID and API_KEY)


def _read_from_jsonbin() -> list:
    url = f"{BASE_URL}/{BIN_ID}/latest"
    request = urllib.request.Request(url)
    request.add_header("X-Master-Key", API_KEY)

    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
            data = payload.get("record", {})
            if isinstance(data, dict):
                events = data.get("events", [])
                if isinstance(events, list):
                    return events
            return []
    except Exception:
        return []


def _write_to_jsonbin(events: list) -> bool:
    url = f"{BASE_URL}/{BIN_ID}"
    request = urllib.request.Request(
        url,
        data=json.dumps({"events": events}).encode("utf-8"),
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


def load_events() -> list:
    """Return stored verification events (most recent last)."""
    if _configured():
        events = _read_from_jsonbin()
        if events:
            return events[-MAX_EVENTS:]
    return list(_MEMORY_EVENTS)[-MAX_EVENTS:]


def record_event(valid: bool, source_id: str = "default_source") -> list:
    """Append one verification event and persist. Returns the log."""
    events = load_events()

    now = datetime.now(timezone.utc)
    events.append(
        {
            "ts": now.isoformat(timespec="seconds"),
            "valid": 1 if valid else 0,
            "source": source_id,
        }
    )
    events = events[-MAX_EVENTS:]

    if _configured():
        if _write_to_jsonbin(events):
            _MEMORY_EVENTS[:] = events
            return events

    _MEMORY_EVENTS[:] = events
    return events


def calculate_behavioral_features(
    current_verification_result: int,
    source_id: str = "default_source",
) -> dict:
    """Compute behavioral features including the current event.

    Mirrors the original CSV-based engine: frequency counts include
    the current event, the failed rate is computed over the combined
    history + current result, and time-since-previous is measured
    against the last stored event.
    """
    events = load_events()

    now = datetime.now(timezone.utc)
    current_hour = now.hour

    current_valid = current_verification_result == 1

    # No previous history.
    if not events:
        return {
            "verification_frequency": 1,
            "source_frequency": 1,
            "failed_verification_rate": (
                0.0 if current_valid else 1.0
            ),
            "time_since_previous": 0,
            "hour": current_hour,
        }

    verification_frequency = len(events) + 1

    failed_events = sum(1 for e in events if int(e.get("valid", 1)) == 0)
    if not current_valid:
        failed_events += 1

    failed_verification_rate = failed_events / verification_frequency

    source_frequency = (
        sum(1 for e in events if e.get("source", "") == source_id) + 1
    )

    time_since_previous = 0
    try:
        previous_timestamp = events[-1].get("ts")
        if previous_timestamp:
            previous_time = datetime.fromisoformat(previous_timestamp)
            difference = now - previous_time
            time_since_previous = max(0, int(difference.total_seconds()))
    except Exception:
        time_since_previous = 0

    return {
        "verification_frequency": verification_frequency,
        "source_frequency": source_frequency,
        "failed_verification_rate": round(failed_verification_rate, 4),
        "time_since_previous": time_since_previous,
        "hour": current_hour,
    }