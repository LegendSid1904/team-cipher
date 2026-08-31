"""RSA-PSS / SHA-256 signing helpers for the Sign step."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_keypair(key_size: int = 2048):
    """Generate an RSA keypair. Returns (private_pem, public_pem) bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_document(document: bytes, private_key_pem: bytes) -> bytes:
    """Sign a document with a PEM private key using RSA-PSS/SHA-256."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        document,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature
