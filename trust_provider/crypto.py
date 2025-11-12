"""Minimal crypto helpers for TP skeleton.

These include simple stubs (Paillier, chameleon hash) for MVP wiring and
real crypto utilities (RSA-OAEP and Ed25519 verify) for the secure request
flow. Replace stubs with production-grade crypto as you iterate.
"""
from dataclasses import dataclass
from typing import Any, Dict
import json
import secrets
import hashlib

# Real crypto bits for the minimal encrypted flow
import base64
from threading import Lock
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519


@dataclass
class PaillierKeypair:
    public: Dict[str, Any]
    private: Dict[str, Any]


def generate_paillier_keypair(nbits: int = 2048) -> PaillierKeypair:
    """Generate a fake Paillier keypair (stub).

    Produces deterministic-like placeholders. Replace with real implementation.
    """
    # WARNING: This is NOT real crypto. Use real Paillier lib in production.
    pub = {"n": secrets.token_hex(nbits // 8), "g": "g_placeholder"}
    priv = {"lambda": secrets.token_hex(nbits // 8), "mu": "mu_placeholder"}
    return PaillierKeypair(public=pub, private=priv)


def paillier_encrypt(pub: Dict[str, Any], plaintext: str) -> str:
    """Stub encrypt: JSON placeholder."""
    payload = {"p": plaintext}
    return json.dumps(payload, ensure_ascii=False)


def paillier_decrypt(priv: Dict[str, Any], ciphertext: str) -> str:
    """Stub decrypt to invert paillier_encrypt."""
    try:
        data = json.loads(ciphertext)
        return data.get("p", "")
    except Exception:
        return ""


def generate_chameleon_hash(message: str) -> Dict[str, str]:
    """Stub for chameleon-hash (returns hash and trapdoor stub)."""
    # Use randomness so each call differs; real CH should support trapdoor usage
    payload = f"{message}|{secrets.token_hex(8)}"
    h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return {"hash": h, "trapdoor": secrets.token_hex(16)}


def canonical_json(obj: Any) -> str:
    """Return canonical JSON string for deterministic hashing/signing."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sign_with_secret(secret: str, data: Any) -> str:
    """Deterministic signature stub using secret + canonical_json(data)."""
    payload = canonical_json(data)
    return sha256_hex(secret + "|" + payload)


def verify_with_secret(secret: str, data: Any, signature: str) -> bool:
    return sign_with_secret(secret, data) == signature


# =========================
# RSA (TP side) for CR flow
# =========================
_RSA_CACHE: Dict[str, Any] = {}
_RSA_LOCK = Lock()
_RSA_PUBLIC_EXPONENT = 65537
_RSA_KEY_SIZE = 2048


def _generate_tp_rsa():
    return rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_SIZE
    )


def get_tp_rsa_private():
    """Singleton in-memory RSA private key for TP (demo only)."""
    if "rsa_priv" in _RSA_CACHE:
        return _RSA_CACHE["rsa_priv"]
    with _RSA_LOCK:
        if "rsa_priv" not in _RSA_CACHE:
            _RSA_CACHE["rsa_priv"] = _generate_tp_rsa()
        return _RSA_CACHE["rsa_priv"]


def get_tp_rsa_public_pem() -> str:
    """Export TP RSA public key in PEM (SubjectPublicKeyInfo)."""
    priv = get_tp_rsa_private()
    pub = priv.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()


def rsa_decrypt_base64(b64_cipher: str) -> bytes:
    """RSA-OAEP decrypt base64-encoded ciphertext with TP private key."""
    ct = base64.b64decode(b64_cipher)
    priv = get_tp_rsa_private()
    pt = priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pt


# ======================================
# Ed25519 verify for user signature check
# ======================================
def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature; returns True/False."""
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pk.verify(signature, message)
        return True
    except Exception:
        return False

