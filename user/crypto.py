"""
User-side crypto helpers.
"""
from typing import Any
import secrets
import hashlib
import json
import base64

# Real crypto for secure request (optional, keeps stubs intact)
from crypto_lib import DL_P, DL_G, DL_Q


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def compute_r_bind() -> str:
    return secrets.token_hex(16)


def compute_af_dl(id_str: str, pk_ap: int, pk_tp: int, r_bind_hex: str) -> int:
    h = int(sha256_hex(id_str), 16) % DL_P
    r = int(r_bind_hex, 16) % DL_P
    return (h * pk_ap % DL_P) * (pk_tp % DL_P) % DL_P * pow(DL_G, r, DL_P) % DL_P


def compute_cmi(pii: dict) -> str:
    """Compute CMI (Content Meta Index) as a hash of PII (stub)."""
    return sha256_hex(canonical_json(pii))


def sign_with_secret(secret: str, data: Any) -> str:
    # Deterministic signature stub to match TP
    return sha256_hex(secret + "|" + canonical_json(data))


 
def dl_generate_user_keypair():
    sk = secrets.randbelow(DL_Q - 1) + 1
    pk = pow(DL_G, sk, DL_P)
    return sk, pk

def schnorr_sign(sk: int, msg: bytes) -> dict:
    k = secrets.randbelow(DL_Q - 1) + 1
    r = pow(DL_G, k, DL_P)
    e = int.from_bytes(hashlib.sha256(r.to_bytes(32, "big") + msg).digest(), "big") % DL_Q
    s = k + e * sk
    return {"r": r, "e": e, "s": s}

def elgamal_encrypt_bytes(pk: int, obj: dict) -> dict:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    k = secrets.randbelow(DL_Q - 1) + 1
    c1 = pow(DL_G, k, DL_P)
    s = pow(pk, k, DL_P)
    key = hashlib.sha256(str(s).encode()).digest()
    ks = (key * ((len(raw) // len(key)) + 1))[: len(raw)]
    c2 = bytes(a ^ b for a, b in zip(raw, ks))
    return {"c1": c1, "c2": base64.b64encode(c2).decode()}
