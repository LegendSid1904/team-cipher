"""SIH26141 Digital Signature Security — FastAPI app.

Deploys to Vercel as a single FastAPI Function (framework preset).

Routes:
  GET  /                      -> landing page
  GET  /sign                  -> sign-page frontend
  GET  /verify                -> verify-page frontend
  POST /api/sign              -> sign a document + register public key
  POST /api/verify            -> verify a document using a stored key
  GET  /api/keys              -> list registered public keys
  GET  /api/health            -> health check
  GET  /api/events            -> recent security events (dashboard)
"""

import os
import sys
import base64
import binascii
import hashlib
from pathlib import Path

# Ensure the _lib package (sibling of main.py) is importable
# regardless of how this module is loaded (uvicorn/vercel/dev).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from _lib.crypto_verify import verify_rsa_pss_signature
from _lib.crypto_sign import generate_keypair, sign_document
from _lib.detector import detect_threat
from _lib import storage, keystore
from _lib import behavioral_store, replay_store

app = FastAPI(
    title="SIH26141 Digital Signature Security",
    description="Quantum-Inspired Cyber Threat Detection for Digital Signatures",
    version="1.0.0",
)

# Serve the frontend static assets (if present).
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
LANDING_HTML = STATIC_DIR / "index.html"
SIGN_HTML = STATIC_DIR / "sign.html"
VERIFY_HTML = STATIC_DIR / "verify.html"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Recognized document extensions. Anything else is treated as a
# possible metadata anomaly.
_KNOWN_EXTENSIONS = {
    "txt", "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "csv", "json", "xml",
    "png", "jpg", "jpeg", "gif",
}


def _serve_page(path: Path):
    if path.exists():
        return FileResponse(str(path))
    raise HTTPException(404, "Page not found")


def _metadata_anomaly(filename) -> int:
    """Flag unusual / missing file extensions as metadata anomaly."""
    if not filename:
        return 1
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return 0 if ext in _KNOWN_EXTENSIONS else 1


def _document_hash(document_data: bytes) -> str:
    return hashlib.sha256(document_data).hexdigest()


# ---------------------------------------------------------------
# Frontend pages
# ---------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index():
    return _serve_page(LANDING_HTML)


@app.get("/sign", include_in_schema=False)
def sign_page():
    return _serve_page(SIGN_HTML)


@app.get("/verify", include_in_schema=False)
def verify_page():
    return _serve_page(VERIFY_HTML)


# ---------------------------------------------------------------
# Health
# ---------------------------------------------------------------
@app.get("/api/health")
def health():
    from _lib import ml_detector
    return {
        "success": True,
        "status": "healthy",
        "events_storage": storage._configured(),
        "keys_storage": keystore._configured(),
        "behavioral_storage": behavioral_store._configured(),
        "replay_storage": replay_store._configured(),
        "ml_loaded": ml_detector.model_loaded(),
        "ml_error": ml_detector.load_error(),
    }


# ---------------------------------------------------------------
# Sign a document + register public key
# ---------------------------------------------------------------
@app.post("/api/sign")
async def sign_document_endpoint(
    document: UploadFile = File(...),
    label: Optional[str] = Form(None),
    name: Optional[str] = Form(None),
    private_key: Optional[UploadFile] = File(None),
):
    document_data = await document.read()
    if not document_data:
        raise HTTPException(400, "Document file is empty.")

    label = (label or "unnamed").strip().lower()

    generated_private = None
    new_key = False

    if private_key is not None:
        # Sign with the user's provided private key, register its public key.
        private_pem = await private_key.read()
        if not private_pem:
            raise HTTPException(400, "Private key file is empty.")
        try:
            signature = sign_document(document_data, private_pem)
        except Exception as e:
            raise HTTPException(400, f"Could not sign with provided private key: {e}")

        # derive public key from private key for registration
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        private_obj = load_pem_private_key(private_pem, password=None)
        public_pem = private_obj.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        key_size = getattr(private_obj, "key_size", 0)
    else:
        # Generate a fresh keypair; register the public key.
        private_pem, public_bytes = generate_keypair(2048)
        signature = sign_document(document_data, private_pem)
        public_pem = public_bytes.decode("utf-8")
        generated_private = base64.b64encode(private_pem).decode("utf-8")
        new_key = True
        key_size = _key_size_of_private(private_pem)

    keystore.register_public_key(label, public_pem, name=name or "")

    return {
        "success": True,
        "label": label,
        "new_key": new_key,
        "key_size": key_size,
        "signature_b64": base64.b64encode(signature).decode("utf-8"),
        "private_key_b64": generated_private,  # only when freshly generated
        "public_key": public_pem,
        "document_name": document.filename or "document",
    }


# ---------------------------------------------------------------
# Verify a document using a stored public key
# ---------------------------------------------------------------
@app.post("/api/verify")
async def verify_document_endpoint(
    document: UploadFile = File(...),
    signature: UploadFile = File(...),
    label: Optional[str] = Form(None),
    public_key: Optional[str] = Form(None),
):
    document_data = await document.read()
    signature_data = await signature.read()

    if not document_data:
        raise HTTPException(400, "Document file is empty.")
    if not signature_data:
        raise HTTPException(400, "Signature file is empty.")

    key_label = (label or "").strip().lower()
    public_key_pem = None

    if public_key and public_key.strip():
        public_key_pem = public_key.strip().encode("utf-8")
    elif key_label:
        record = keystore.get_public_key(key_label)
        if record is None:
            raise HTTPException(
                404,
                f"No public key registered for label '{key_label}'. Sign the document first to register a key, or check the label.",
            )
        public_key_pem = record["public_key"].encode("utf-8")
        key_label = record.get("name") or key_label
    else:
        raise HTTPException(400, "Provide the signer label or paste the public key.")

    verification = verify_rsa_pss_signature(
        document_data, signature_data, public_key_pem
    )

    valid = verification["valid"]
    key_size = verification["key_size"]

    # ----- replay detection (before recording this request) ----
    document_hash = _document_hash(document_data)
    replay_detected = False
    try:
        replay_detected = replay_store.check_replay(document_hash)
    except Exception:
        replay_detected = False

    # ----- behavioral features (before recording this request) -
    source_id = key_label or "pasted_key"
    metadata_anomaly = _metadata_anomaly(document.filename)
    try:
        behavioral = behavioral_store.calculate_behavioral_features(
            current_verification_result=1 if valid else 0,
            source_id=source_id,
        )
    except Exception:
        behavioral = {
            "verification_frequency": 1,
            "source_frequency": 1,
            "failed_verification_rate": 0.0 if valid else 1.0,
            "time_since_previous": 0,
            "hour": 0,
        }

    # ----- unified detection (rules + ML) -----------------------
    result = detect_threat(
        valid=valid,
        key_size=key_size,
        verification_frequency=behavioral["verification_frequency"],
        source_frequency=behavioral["source_frequency"],
        failed_verification_rate=behavioral["failed_verification_rate"],
        metadata_anomaly=metadata_anomaly,
        replay_indicator=1 if replay_detected else 0,
        failed_attempts=0 if valid else 1,
    )

    display_name = document.filename or "document"

    event_payload = {
        "timestamp": _now(),
        "filename": display_name,
        "verification": "VALID" if valid else "INVALID",
        "risk_score": result["risk_score"],
        "threat_level": result["threat_level"],
        "attack_category": result["attack_category"],
        "assessment": result["assessment"],
        "ml_prediction": result["ml_prediction"],
        "ml_threat_probability": result["ml_threat_probability"],
        "replay_detected": replay_detected,
    }
    storage.add_event(event_payload)

    # ----- persist state for future requests --------------------
    try:
        replay_store.record_document(document_hash)
    except Exception:
        pass

    try:
        behavioral_store.record_event(valid=valid, source_id=source_id)
    except Exception:
        pass

    return {
        "success": True,
        "result": {
            **result,
            "document_name": display_name,
            "document_size": len(document_data),
            "signature_size": len(signature_data),
            "key_size": key_size,
            "replay_detected": replay_detected,
        },
        "key_label": key_label,
        "event": event_payload,
    }


# ---------------------------------------------------------------
# Registered keys
# ---------------------------------------------------------------
@app.get("/api/keys")
def list_keys():
    return {"success": True, "keys": keystore.list_labels()}


# ---------------------------------------------------------------
# Events (dashboard)
# ---------------------------------------------------------------
@app.get("/api/events")
def events():
    return {"success": True, "events": storage.get_events()}


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _key_size_of_private(private_pem: bytes) -> int:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        obj = load_pem_private_key(private_pem, password=None)
        k = getattr(obj, "key_size", 0)
        return int(k) if k else 0
    except Exception:
        return 0