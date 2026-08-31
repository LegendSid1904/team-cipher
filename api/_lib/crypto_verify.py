from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def verify_rsa_pss_signature(
    document: bytes,
    signature: bytes,
    public_key_pem: bytes
) -> dict:
    """Verify an RSA-PSS / SHA-256 signature.

    Returns a dict with keys:
      - valid: bool
      - error: str | None
      - key_size: int  (from the loaded public key, -1 if unknown)
    """
    try:
        public_key = load_pem_public_key(public_key_pem)
    except Exception as e:
        return {
            "valid": False,
            "error": f"Could not load public key: {e}",
            "key_size": -1,
        }

    key_size = getattr(public_key, "key_size", None)
    key_size = int(key_size) if key_size else -1

    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "valid": True,
            "error": None,
            "key_size": key_size,
        }
    except (InvalidSignature, ValueError):
        return {
            "valid": False,
            "error": "Signature does not match the document and public key.",
            "key_size": key_size,
        }
    except Exception as e:
        return {
            "valid": False,
            "error": f"Signature verification failed: {e}",
            "key_size": key_size,
        }
