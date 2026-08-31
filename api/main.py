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


def _serve_page(path: Path):
    if path.exists():
        return FileResponse(str(path))
    raise HTTPException(404, "Page not found")


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
    return {
        "success": True,
        "status": "healthy",
        "events_storage": storage._configured(),
        "keys_storage": keystore._configured(),
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
        "document_name": document.filename or "document",
    }


# ---------------------------------------------------------------
# Verify a document using a stored public key
# ---------------------------------------------------------------
@app.post("/api/verify")
async def verify_document_endpoint(
    document: UploadFile = File(...),
    signature: UploadFile = File(...),
    label: str = Form(...),
):
    document_data = await document.read()
    signature_data = await signature.read()

    if not document_data:
        raise HTTPException(400, "Document file is empty.")
    if not signature_data:
        raise HTTPException(400, "Signature file is empty.")

    label = label.strip().lower()
    record = keystore.get_public_key(label)
    if record is None:
        raise HTTPException(
            404,
            f"No public key registered for label '{label}'. Sign the document first to register a key, or check the label.",
        )

    public_key_pem = record["public_key"].encode("utf-8")

    verification = verify_rsa_pss_signature(
        document_data, signature_data, public_key_pem
    )

    valid = verification["valid"]
    key_size = verification["key_size"]

    result = detect_threat(valid, key_size)

    display_name = document.filename or "document"

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
            # convenience: threat detection on document fingerprint
        },
        "key_label": label,
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
