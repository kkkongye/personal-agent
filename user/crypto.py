"""User-side crypto helpers (deterministic stubs).

These mirror TP's stub helpers to keep tests deterministic.
Replace with real crypto (e.g., HKDF/HMAC, Paillier, etc.) in production.
"""
from typing import Any
import secrets
import hashlib
import json
import base64

# Real crypto for secure request (optional, keeps stubs intact)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_r_bind() -> str:
    # Binding randomness (stub)
    return secrets.token_hex(16)


def compute_af(pii: dict, bi: dict, r_bind: str, pk_ap: str = "ap.pk.placeholder") -> str:
    """Compute AF from PII/BI/r_bind/pk_ap (deterministic stub).

    AF := sha256( canonical_json({pii,bi,r_bind,pk_ap}) )
    """
    payload = {"pii": pii, "bi": bi, "r_bind": r_bind, "pk_ap": pk_ap}
    return sha256_hex(canonical_json(payload))


def compute_cmi(pii: dict) -> str:
    """Compute CMI (Content Meta Index) as a hash of PII (stub)."""
    return sha256_hex(canonical_json(pii))


def sign_with_secret(secret: str, data: Any) -> str:
    # Deterministic signature stub to match TP
    return sha256_hex(secret + "|" + canonical_json(data))


# ================================
# Secure flow: Ed25519 + RSA-OAEP
# ================================
def generate_user_ed25519():
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_bytes = sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return sk_bytes, pk_bytes


def sign_r_bind(sk_bytes: bytes, r_bind: bytes) -> bytes:
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(sk_bytes)
    return sk.sign(r_bind)


def verify_r_bind_signature(pk_bytes: bytes, r_bind: bytes, sig: bytes) -> bool:
    pk = ed25519.Ed25519PublicKey.from_public_bytes(pk_bytes)
    try:
        pk.verify(sig, r_bind)
        return True
    except Exception:
        return False


def _load_tp_rsa_public(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode())


def encrypt_issue_plaintext(tp_pub_pem: str, obj: dict) -> str:
    """RSA-OAEP encrypt JSON plaintext with TP public key, return base64 string."""
    pub = _load_tp_rsa_public(tp_pub_pem)
    raw = json.dumps(obj, separators=(",", ":")).encode()
    ct = pub.encrypt(
        raw,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()
