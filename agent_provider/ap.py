from typing import Any, Dict
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
from trust_provider.crypto import (
    dl_generate_keypair,
    elgamal_decrypt_bytes,
    elgamal_encrypt_bytes as tp_elg_encrypt_bytes,
    schnorr_sign,
    canonical_json,
    sha256_hex,
    DL_P,
)

router = APIRouter()

AP_SK, AP_PK = dl_generate_keypair()


class APInbound(BaseModel):
    ar: Dict[str, Any]
    user_pub: int


@router.get("/ap/public_keys")
def ap_public_keys() -> Dict[str, Any]:
    return {"ap_dlog_pk": AP_PK}


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
    apa = {"APid": apid, "APproof": sig}
    pa = {"APM": apm_prime, "APA": apa}

    rb2 = _rand_int()
    par_obj = {"r_bind2": rb2, "PHC": phc, "PA": pa}
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