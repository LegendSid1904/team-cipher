"""SIH26141 Digital Signature Security — FastAPI app.

Deploys to Vercel as a single FastAPI Function (framework preset).

Routes:
  GET  /                    -> the frontend (index.html)
  POST /api/verify          -> verify signature + threat detection
  POST /api/detect          -> threat detection on supplied event
  GET  /api/events          -> recent security events (dashboard)
  GET  /api/health          -> health check
"""

import os
import sys
from pathlib import Path

# Ensure the _lib package (sibling of main.py) is importable
# regardless of how this module is loaded (uvicorn/vercel/dev).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from _lib.crypto_verify import verify_rsa_pss_signature
from _lib.detector import detect_threat
from _lib import storage

app = FastAPI(
    title="SIH26141 Digital Signature Security Analyzer",
    description="Quantum-Inspired Cyber Threat Detection for Digital Signatures",
    version="0.9.0",
)

# Serve the frontend static assets (if present).
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
FRONTEND_HTML = STATIC_DIR / "index.html"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------
# Root -> frontend
# ---------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index():
    if FRONTEND_HTML.exists():
        return FileResponse(str(FRONTEND_HTML))
    return JSONResponse({"success": True, "message": "Backend online"})


# ---------------------------------------------------------------
# Health
# ---------------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "success": True,
        "status": "healthy",
        "storage_configured": storage._configured(),
    }


# ---------------------------------------------------------------
# Verify + detect
# ---------------------------------------------------------------
@app.post("/api/verify")
async def verify_and_detect(
    document: UploadFile = File(...),
    signature: UploadFile = File(...),
    public_key: UploadFile = File(...),
    filename: Optional[str] = File(None)
):
    document_data = await document.read()
    signature_data = await signature.read()
    public_key_data = await public_key.read()

    if not document_data:
        raise HTTPException(400, "Document file is empty.")
    if not signature_data:
        raise HTTPException(400, "Signature file is empty.")
    if not public_key_data:
        raise HTTPException(400, "Public key file is empty.")

    verification = verify_rsa_pss_signature(
        document_data, signature_data, public_key_data
    )

    valid = verification["valid"]
    key_size = verification["key_size"]

    result = detect_threat(valid, key_size)

    display_name = filename or document.filename or "document"

    event_payload = {
        "timestamp": _now(),
        "filename": display_name,
        "verification": "VALID" if valid else "INVALID",
        "risk_score": result["risk_score"],
        "threat_level": result["threat_level"],
        "attack_category": result["attack_category"],
        "assessment": result["assessment"],
    }
    storage.add_event(event_payload)

    return {
        "success": True,
        "result": {
            **result,
            "document_name": display_name,
            "document_size": len(document_data),
            "signature_size": len(signature_data),
            "key_size": key_size,
        },
        "event": event_payload,
    }


# ---------------------------------------------------------------
# Detect (threat analysis only, no signature check)
# ---------------------------------------------------------------
class EventModel(BaseModel):
    valid: bool = False
    key_size: int = 2048


@app.post("/api/detect")
def detect(event: EventModel):
    result = detect_threat(event.valid, event.key_size)
    event_payload = {
        "timestamp": _now(),
        "filename": "manual-analysis",
        "verification": "VALID" if event.valid else "INVALID",
        "risk_score": result["risk_score"],
        "threat_level": result["threat_level"],
        "attack_category": result["attack_category"],
        "assessment": result["assessment"],
    }
    storage.add_event(event_payload)
    return {"success": True, "result": result, "event": event_payload}


# ---------------------------------------------------------------
# Events (dashboard)
# ---------------------------------------------------------------
@app.get("/api/events")
def events():
    return {"success": True, "events": storage.get_events()}


def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
