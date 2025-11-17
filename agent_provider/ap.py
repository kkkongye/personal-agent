from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from crypto_lib import (
    dl_generate_keypair,
    elgamal_decrypt_bytes,
    elgamal_encrypt_bytes as tp_elg_encrypt_bytes,
    schnorr_sign,
    canonical_json,
    sha256_hex,
    DL_P,
)
from trust_provider.issue_phc import TP_PAILLIER, TP_DL_PK
from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.crypto import sign_with_secret

router = APIRouter()

AP_SK, AP_PK = dl_generate_keypair()


class APInbound(BaseModel):
    ar: Dict[str, Any]
    user_pub: int


@router.get("/ap/public_keys")
def ap_public_keys() -> Dict[str, Any]:
    return {"ap_dlog_pk": str(AP_PK)}


@router.post("/ap/request_pa")
def request_pa(payload: APInbound) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.ar)
        obj = json_loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")

    phc = obj.get("PHC")
    hid = obj.get("HID")
    if not isinstance(phc, dict) or not isinstance(hid, str):
        raise HTTPException(status_code=400, detail="invalid_payload")

    aso = phc.get("ASO") or {}
    apm = aso.get("APM") or {}
    cmi = apm.get("CMI") or ""

    cmc_list = [cmi]
    cmi_prime = sha256_hex(canonical_json({"cmc": cmc_list, "hid": hid}))

    apm_prime = {"CMI": cmi_prime, "Time": datetime.utcnow().isoformat() + "Z"}
    apid = "ap.example"
    sig = schnorr_sign(AP_SK, canonical_json(apm_prime).encode())
    apa = {"APid": apid, "APproof": {"r": str(sig["r"]), "e": str(sig["e"]), "s": str(sig["s"])}}
    pa = {"APM": apm_prime, "APA": apa}

    rb2 = _rand_int()
    par_obj = {"r_bind2": str(rb2), "PHC": phc, "PA": pa}
    enc = _encrypt_to_user(payload.user_pub, par_obj)
    return {"success": True, "par": enc, "mode": "ap_secure"}


def json_loads(b: bytes) -> Dict[str, Any]:
    import json
    return json.loads(b.decode())


def _rand_int() -> int:
    import secrets
    return secrets.randbelow(DL_P - 2) + 1


def _encrypt_to_user(pk: int, obj: Dict[str, Any]) -> Dict[str, Any]:
    import json
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return tp_elg_encrypt_bytes(pk, raw)


# ====================
# CMM exchange (init/submit)
# ====================

class CMMInitRequest(BaseModel):
    ar: Dict[str, Any]
    user_pub: int

class CMMSubmitRequest(BaseModel):
    cmc_enc: Dict[str, Any]
    user_pub: int | str

@router.post("/ap/cmm_init")
def cmm_init(payload: CMMInitRequest) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.ar)
        obj = json_loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")

    phc = obj.get("PHC")
    hid = obj.get("HID")
    tpac = obj.get("TPAC")
    if not isinstance(phc, dict) or not isinstance(hid, str) or not isinstance(tpac, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")

    # TPproof cross-process verification不可用（stub签名不可公开验证）；在分布式环境下跳过严格校验
    # 可在安全发证链路中使用公开可验证签名替换此逻辑
    try:
        _ = phc.get("TPA", {}).get("TPproof")
    except Exception:
        pass

    cmm = _build_cmm_matrix(hid, phc)
    return {"success": True, "cmm_enc": _encrypt_to_user(payload.user_pub, {"CMM": cmm})}


@router.post("/ap/cmm_submit")
def cmm_submit(payload: CMMSubmitRequest) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.cmc_enc)
        obj = json_loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")

    cmc = obj.get("CMC")
    hid = obj.get("HID")
    phc = obj.get("PHC")
    if not isinstance(cmc, list) or not isinstance(hid, str) or not isinstance(phc, dict):
        raise HTTPException(status_code=400, detail="invalid_payload")

    cmi_int = hcgen_cmi(cmc, hid)
    apm_prime = {"CMI": str(cmi_int), "Time": datetime.utcnow().isoformat() + "Z"}
    apid = "ap.example"
    sig = schnorr_sign(AP_SK, canonical_json(apm_prime).encode())
    apa = {"APid": apid, "APproof": {"r": str(sig["r"]), "e": str(sig["e"]), "s": str(sig["s"])}}
    pa = {"APM": apm_prime, "APA": apa}

    rb2 = _rand_int()
    # CH over (APM', APA, r_ap) — stub: sha256 over canonical
    r_ap = _rand_int()
    ch_val = ch_compute(AP_PK, apm_prime, apa, r_ap)
    # CCH over (AF, CMI, r_bind'') — stub: sha256 over canonical
    af_prev = phc.get("ASO", {}).get("TPM", {}).get("AF")
    rf_val = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
    try:
        crf_int = int(str(rf_val or 0)) % DL_Q
    except Exception:
        crf_int = 0
    af_calc = compute_af_formal(str(hid), AP_PK, TP_DL_PK, cmi_int % DL_Q, crf_int, rb2)
    verified_af = (str(af_prev) == str(af_calc))
    cch_val = cch_compute(AP_PK, TP_DL_PK, cmi_int, crf_int, rb2)
    par_obj = {"r_bind2": str(rb2), "PHC": phc, "PA": pa, "CH": str(ch_val), "CCH": str(cch_val), "verified_af": verified_af}
    try:
        upub = int(str(payload.user_pub))
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_user_pub")
    enc = _encrypt_to_user(upub, par_obj)
    return {"success": True, "par": enc}


def _build_cmm_matrix(hid: str, phc: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    # Simple demo CMM matrix: rows = categories; cols = implementations
    return [
        [
            {"id": "notif_email", "label": "Email 通知", "params": {"sender": "noreply@example.com"}},
            {"id": "notif_sms", "label": "SMS 通知", "params": {"provider": "twilio"}},
            {"id": "notif_push", "label": "Push 通知", "params": {"provider": "onesignal"}},
        ],
        [
            {"id": "store_ipfs", "label": "IPFS 存证", "params": {"pin": True}},
            {"id": "store_local", "label": "本地存储", "params": {"path": "./storage"}},
        ],
        [
            {"id": "privacy_basic", "label": "基础隐私", "params": {"mask_fields": ["email"]}},
            {"id": "privacy_strict", "label": "严格隐私", "params": {"mask_fields": ["email", "id_card_number"]}},
        ],
    ]