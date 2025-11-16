"""HTTP client for interacting with TP endpoints remotely.

Adds secure issuance method using encrypted request + Ed25519 signature.
Legacy plaintext method retained for compatibility/tests.
"""
from typing import Any, Dict
import httpx
import secrets
import time
import base64
from .crypto import (
    compute_cmi,
    compute_r_bind,
    dl_generate_user_keypair,
    schnorr_sign,
    elgamal_encrypt_bytes,
    compute_af_dl,
    sha256_hex,
    canonical_json,
)
from .models import UserInfo, PHCResponse


def request_phc_remote(base_url: str, user: UserInfo) -> PHCResponse:
    """Generate AF/CMI then POST to TP /v1/tp/issue_phc endpoint.

    Assumes TP router mounted under /v1/tp.
    Sends flat fields (af, cmi, cdid, ecid) which TP service will expand.
    """
    r_bind = compute_r_bind()
    af = sha256_hex(canonical_json({"pii": user.pii.model_dump(), "bi": user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
    cmi = compute_cmi(user.pii.model_dump())

    payload = {
        "af": af,
        "cmi": cmi,
        "cdid": user.cdid,
        "ecid": user.ecid,
    }
    url = base_url.rstrip("/") + "/v1/tp/issue_phc"
    resp = httpx.post(url, json=payload, timeout=10.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)


def request_phc_secure(base_url: str, user: UserInfo) -> PHCResponse:
    """Secure issuance: encrypt payload + sign r_bind.

    Flow:
      1. Fetch TP RSA public key (/v1/tp/public_keys)
      2. Generate ephemeral Ed25519 keypair (could be persisted by caller)
      3. Generate r_bind (32 bytes)
      4. Build compact plaintext JSON {AF (base64 digest), CDID, ECID, r_bind_b64, timestamp}
         (CMI omitted to keep RSA payload size small; server fills placeholder)
      5. RSA-OAEP encrypt -> base64 -> cr
      6. Sign raw r_bind with Ed25519 -> sig
      7. POST to /v1/tp/issue_phc_secure
    """
    pub_resp = httpx.get(base_url.rstrip("/") + "/v1/tp/public_keys", timeout=10.0)
    pub_resp.raise_for_status()
    tp_keys = pub_resp.json()
    tp_dlog_pk = tp_keys["tp_dlog_pk"]
    ap_dlog_pk = tp_keys["ap_dlog_pk"]

    sk_a, pk_a = dl_generate_user_keypair()
    r_bind_int = int(secrets.token_hex(16), 16)
    af_val = compute_af_dl(user.pii.id_number, ap_dlog_pk, tp_dlog_pk, hex(r_bind_int)[2:])
    plaintext = {"AF": af_val, "ID": user.pii.id_number, "BI": user.bi.model_dump(), "PII": user.pii.model_dump(), "pk_ap": ap_dlog_pk, "r_bind": r_bind_int, "timestamp": int(time.time())}
    cr = elgamal_encrypt_bytes(tp_dlog_pk, plaintext)
    sig = schnorr_sign(sk_a, str(r_bind_int).encode())
    payload = {"cr": cr, "user_pub": pk_a, "sig": sig}
    url = base_url.rstrip("/") + "/v1/tp/issue_phc_secure"
    resp = httpx.post(url, json=payload, timeout=15.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)
