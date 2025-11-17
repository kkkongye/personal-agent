"""
Unified cryptographic helpers (DL group, ElGamal, Schnorr, CH/CCH, AF) shared across TP/AP/User.
"""
from dataclasses import dataclass
from typing import Any, Dict, Tuple
import json
import secrets
import hashlib
import base64

@dataclass
class PaillierKeypair:
    public: Dict[str, Any]
    private: Dict[str, Any]

def generate_paillier_keypair(nbits: int = 128) -> PaillierKeypair:
    n = int.from_bytes(secrets.token_bytes(nbits // 8), "big") | 1
    g = n + 1
    lam = int.from_bytes(secrets.token_bytes(nbits // 8), "big") | 1
    pub = {"n": n, "g": g}
    priv = {"lambda": lam}
    return PaillierKeypair(public=pub, private=priv)

def paillier_encrypt(pub: Dict[str, Any], m: int) -> int:
    n = pub["n"]
    g = pub["g"]
    r = int.from_bytes(secrets.token_bytes(16), "big") % n or 1
    n2 = n * n
    return (pow(g, m % n, n2) * pow(r, n, n2)) % n2

def paillier_decrypt(priv: Dict[str, Any], ciphertext: int) -> int:
    return 0

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def sign_with_secret(secret: Any, data: Any) -> str:
    payload = canonical_json(data)
    return sha256_hex(str(secret) + "|" + payload)

def verify_with_secret(secret: str, data: Any, signature: str) -> bool:
    return sign_with_secret(secret, data) == signature

DL_P = (1 << 127) - 1
DL_Q = DL_P - 1
DL_G = 5

def dl_generate_keypair() -> Tuple[int, int]:
    sk = secrets.randbelow(DL_Q - 1) + 1
    pk = pow(DL_G, sk, DL_P)
    return sk, pk

def hash_to_int(b: bytes) -> int:
    return int.from_bytes(hashlib.sha256(b).digest(), "big") % DL_P

def schnorr_sign(sk: int, msg: bytes) -> Dict[str, int]:
    k = secrets.randbelow(DL_Q - 1) + 1
    r = pow(DL_G, k, DL_P)
    e = hash_to_int(r.to_bytes(32, "big") + msg) % DL_Q
    s = k + e * sk
    return {"r": r, "e": e, "s": s}

def schnorr_verify(pk: int, msg: bytes, sig: Dict[str, int]) -> bool:
    r = sig.get("r")
    e = sig.get("e")
    s = sig.get("s")
    if e is None or s is None:
        return False
    e2 = hash_to_int(int(r).to_bytes(32, "big") + msg) % DL_Q
    if e2 != e:
        return False
    lhs = pow(DL_G, s, DL_P)
    rhs = (int(r) * pow(pk, e, DL_P)) % DL_P
    return lhs == rhs

def elgamal_encrypt_bytes(pk: int, pt: bytes) -> Dict[str, Any]:
    k = secrets.randbelow(DL_Q - 1) + 1
    c1 = pow(DL_G, k, DL_P)
    s = pow(pk, k, DL_P)
    key = hashlib.sha256(str(s).encode()).digest()
    ks = (key * ((len(pt) // len(key)) + 1))[: len(pt)]
    c2 = bytes(a ^ b for a, b in zip(pt, ks))
    return {"c1": c1, "c2": base64.b64encode(c2).decode()}

def elgamal_decrypt_bytes(sk: int, c: Dict[str, Any]) -> bytes:
    c1 = int(c["c1"])
    c2 = base64.b64decode(c["c2"])
    s = pow(c1, sk, DL_P)
    key = hashlib.sha256(str(s).encode()).digest()
    ks = (key * ((len(c2) // len(key)) + 1))[: len(c2)]
    pt = bytes(a ^ b for a, b in zip(c2, ks))
    return pt

def crf_encrypt(pk: int, rf: int, r_bind: int) -> Dict[str, Any]:
    obj = {"RF": rf, "r_bind": r_bind}
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return elgamal_encrypt_bytes(pk, raw)

def compute_af(id_str: str, pk_ap: int, pk_tp: int, r_bind: int) -> int:
    h = hash_to_int(id_str.encode())
    return (h * pk_ap % DL_P) * (pk_tp % DL_P) % DL_P * pow(DL_G, r_bind % DL_Q, DL_P) % DL_P

def compute_af_formal(id_str: str, pk_ap: int, pk_tp: int, cmi_int: int, crf_int: int, r_bind_int: int) -> int:
    h = hash_to_int(id_str.encode())
    term_ap = pow(pk_ap % DL_P, cmi_int % DL_Q, DL_P)
    term_tp = pow(pk_tp % DL_P, crf_int % DL_Q, DL_P)
    term_r = pow(DL_G, r_bind_int % DL_Q, DL_P)
    return (((h * term_ap) % DL_P) * term_tp % DL_P) * term_r % DL_P

def kdf_s1(lam: int, sk_tp: int, rf: int) -> bytes:
    s = f"{lam}|{sk_tp}|{rf}".encode()
    return hashlib.sha256(s).digest()

def sym_encrypt(key: bytes, pt: bytes) -> str:
    ks = hashlib.sha256(key).digest()
    stream = (ks * ((len(pt) // len(ks)) + 1))[: len(pt)]
    ct = bytes(a ^ b for a, b in zip(pt, stream))
    return base64.b64encode(ct).decode()

def sym_decrypt(key: bytes, ct_b64: str) -> bytes:
    ct = base64.b64decode(ct_b64)
    ks = hashlib.sha256(key).digest()
    stream = (ks * ((len(ct) // len(ks)) + 1))[: len(ct)]
    return bytes(a ^ b for a, b in zip(ct, stream))

def cch_hash(sk_tp: int, af: int, crf: Dict[str, Any], r_bind_prime: int) -> str:
    payload = canonical_json({"af": af, "crf": crf, "rb": r_bind_prime, "k": sk_tp})
    return sha256_hex(payload)

def hcgen_cmi(cmc: Any, hid: str) -> int:
    payload = canonical_json({"cmc": cmc, "hid": hid}).encode()
    return hash_to_int(payload) % DL_Q

def ch_compute(ap_pk: int, apm: Dict[str, Any], apa: Dict[str, Any], r_ap: int) -> int:
    payload = canonical_json({"APM": apm, "APA": apa}).encode()
    h = hash_to_int(payload) % DL_Q
    return (pow(DL_G, h, DL_P) * pow(ap_pk % DL_P, r_ap % DL_Q, DL_P)) % DL_P

def cch_compute(pk_ap: int, pk_tp: int, cmi_int: int, crf_int: int, r_int: int) -> int:
    term_ap = pow(pk_ap % DL_P, cmi_int % DL_Q, DL_P)
    term_tp = pow(pk_tp % DL_P, crf_int % DL_Q, DL_P)
    term_r = pow(DL_G, r_int % DL_Q, DL_P)
    return ((term_ap * term_tp) % DL_P) * term_r % DL_P

def ipfs_put(content: str) -> str:
    cid = None
    try:
        import os, requests
        url = os.environ.get("IPFS_API_URL")
        if url:
            files = {"file": ("secinfo.txt", content.encode())}
            r = requests.post(url.rstrip("/") + "/api/v0/add?pin=true", files=files, timeout=5)
            r.raise_for_status()
            data = r.json() if r.headers.get("content-type","" ).startswith("application/json") else None
            if data and "Hash" in data:
                cid = data["Hash"]
    except Exception:
        cid = None
    if not cid:
        cid = "cid:" + sha256_hex(content)
    try:
        import os
        root = os.path.join(os.getcwd(), "ipfs_store")
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, cid.replace("/", "_")), "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass
    return cid

def ipfs_get(cid: str) -> str:
    try:
        import os, requests
        url = os.environ.get("IPFS_API_URL")
        if url:
            r = requests.post(url.rstrip("/") + "/api/v0/cat", data={"arg": cid}, timeout=5)
            r.raise_for_status()
            return r.text
    except Exception:
        pass
    try:
        import os
        root = os.path.join(os.getcwd(), "ipfs_store")
        with open(os.path.join(root, cid.replace("/", "_")), "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""