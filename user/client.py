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
    compute_af,
    compute_cmi,
    compute_r_bind,
    generate_user_ed25519,
    sign_r_bind,
    encrypt_issue_plaintext,
)
from .models import UserInfo, PHCResponse


def request_phc_remote(base_url: str, user: UserInfo) -> PHCResponse:
    """Generate AF/CMI then POST to TP /v1/tp/issue_phc endpoint.

    Assumes TP router mounted under /v1/tp.
    Sends flat fields (af, cmi, cdid, ecid) which TP service will expand.
    """
    r_bind = compute_r_bind()
    af = compute_af(user.pii.model_dump(), user.bi.model_dump(), r_bind)
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
    tp_encrypt_pk = tp_keys["tp_encrypt_pk"]

    sk_bytes, pk_bytes = generate_user_ed25519()
    r_bind_bytes = secrets.token_bytes(32)
    af_hex = compute_af(user.pii.model_dump(), user.bi.model_dump(), r_bind_bytes.hex())
    af_b64 = base64.b64encode(bytes.fromhex(af_hex)).decode()

    plaintext = {
        "AF": af_b64,
        "CDID": user.cdid,
        "ECID": user.ecid,
        "r_bind_b64": base64.b64encode(r_bind_bytes).decode(),
        "timestamp": int(time.time()),
    }
    cr_b64 = encrypt_issue_plaintext(tp_encrypt_pk, plaintext)
    sig_bytes = sign_r_bind(sk_bytes, r_bind_bytes)

    payload = {
        "cr": cr_b64,
        "user_pub": base64.b64encode(pk_bytes).decode(),
        "sig": base64.b64encode(sig_bytes).decode(),
    }
    url = base_url.rstrip("/") + "/v1/tp/issue_phc_secure"
    resp = httpx.post(url, json=payload, timeout=15.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)
