"""HTTP client for interacting with TP/AP endpoints remotely."""
from typing import Any, Dict
import httpx
import secrets
import time
import json
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
    r_bind = compute_r_bind()
    af = sha256_hex(canonical_json({"pii": user.pii.model_dump(), "bi": user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
    cmi = compute_cmi(user.pii.model_dump())
    payload = {"af": af, "cmi": cmi, "cdid": user.cdid, "ecid": user.ecid}
    url = base_url.rstrip("/") + "/v1/tp/issue_phc"
    resp = httpx.post(url, json=payload, timeout=10.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)


def request_phc_secure(base_url: str, user: UserInfo) -> PHCResponse:
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


def request_pa_remote(base_url: str, phc: Dict[str, Any], user: UserInfo) -> Dict[str, Any]:
    pub_resp = httpx.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
    pub_resp.raise_for_status()
    ap_keys = pub_resp.json()
    ap_dlog_pk = ap_keys["ap_dlog_pk"]
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex(user.pii.id_number)
    tpac = phc.get("TPA") if isinstance(phc, dict) else {}
    ar_plain = {"PHC": phc, "HID": hid, "TPAC": tpac}
    ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
    payload = {"ar": ar, "user_pub": pk_a}
    url = base_url.rstrip("/") + "/v1/ap/request_pa"
    resp = httpx.post(url, json=payload, timeout=15.0)
    resp.raise_for_status()
    data = resp.json()
    par = data.get("par")
    raw = _elg_decrypt(sk_a, par)
    return json.loads(raw.decode())


def _elg_decrypt(sk: int, c: Dict[str, Any]) -> bytes:
    from trust_provider.crypto import elgamal_decrypt_bytes
    return elgamal_decrypt_bytes(sk, c)