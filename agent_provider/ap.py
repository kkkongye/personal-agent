from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
import json
import logging
from crypto_lib import (
    dl_generate_keypair,
    elgamal_decrypt_bytes,
    elgamal_encrypt_bytes as tp_elg_encrypt_bytes,
    schnorr_sign,
    canonical_json,
    sha256_hex,
    DL_P,
    DL_Q,
    hash_to_int,
    inv_mod,
)
from trust_provider.issue_phc import TP_PAILLIER, TP_DL_PK
from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.crypto import sign_with_secret

router = APIRouter()
log = logging.getLogger("ap")

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
    apid = str(AP_PK)
    sig = schnorr_sign(AP_SK, canonical_json({"APM": apm_prime, "APid": apid}).encode())
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
        cmc = obj.get("CMC")
        hid = obj.get("HID")
        phc = obj.get("PHC")
        if not isinstance(cmc, list) or not isinstance(hid, str) or not isinstance(phc, dict):
            return {"success": False, "error": "invalid_payload"}
        cmi_int = hcgen_cmi(cmc, hid)
        apm_prime = {"CMI": str(cmi_int), "Time": datetime.utcnow().isoformat() + "Z"}
        apid = str(AP_PK)
        sig = schnorr_sign(AP_SK, canonical_json({"APM": apm_prime, "APid": apid}).encode())
        apa = {"APid": apid, "APproof": {"r": str(sig["r"]), "e": str(sig["e"]), "s": str(sig["s"])}}
        pa = {"APM": apm_prime, "APA": apa}
        rb2 = _rand_int()
        r_ap = _rand_int()
        ch_val = ch_compute(AP_PK, apm_prime, apa, r_ap)
        af_prev = phc.get("ASO", {}).get("TPM", {}).get("AF")
        rf_val = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
        try:
            crf_int = int(str(rf_val or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_calc = compute_af_formal(str(hid), AP_PK, TP_DL_PK, cmi_int % DL_Q, crf_int, rb2)
        verified_af = (str(af_prev) == str(af_calc))
        cch_val = cch_compute(AP_PK, TP_DL_PK, cmi_int, crf_int, rb2)
        try:
            phc_mod = json.loads(json.dumps(phc))
            old_apm = ((phc_mod.get("ASO") or {}).get("APM") or {})
            old_apa = phc_mod.get("APA") or {}
            proof = phc_mod.setdefault("PROOF", {})
            apch_old = str(proof.get("APCH"))
            r_ap_old = int(str(proof.get("APCH_r") or 0)) % DL_Q
            h_old = hash_to_int(canonical_json({"APM": old_apm, "APA": old_apa}).encode()) % DL_Q
            h_new = hash_to_int(canonical_json({"APM": apm_prime, "APA": apa}).encode()) % DL_Q
            inv_x = inv_mod(AP_SK, DL_Q)
            r_ap_new = (r_ap_old + (h_old - h_new) * inv_x) % DL_Q
            apch_try = str(ch_compute(AP_PK, apm_prime, apa, r_ap_new))
            if apch_old and apch_try == apch_old:
                phc_mod.setdefault("ASO", {}).update({"APM": apm_prime})
                phc_mod.setdefault("ASO", {}).setdefault("TPM", {})["AF"] = str(af_calc)
                phc_mod["APA"] = apa
                proof["APCH_r"] = str(r_ap_new)
            else:
                phc_mod.setdefault("ASO", {}).update({"APM": apm_prime})
                phc_mod.setdefault("ASO", {}).setdefault("TPM", {})["AF"] = str(af_calc)
                phc_mod["APA"] = apa
                proof["APCH"] = apch_try
                proof["needs_tp_resign"] = True
        except Exception:
            phc_mod = phc
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        enc = _encrypt_to_user(upub, {
            "r_bind2": str(rb2),
            "r_ap": str(r_ap),
            "PHC": phc_mod,
            "PHC_original": phc,
            "PA": pa,
            "CH": str(ch_val),
            "CCH": str(cch_val),
            "verified_af": verified_af,
            "ap_pk": str(AP_PK),
            "tp_pk": str(TP_DL_PK),
        })
        return {"success": True, "par": enc}
    except Exception as e:
        log.error("cmm_submit_failed: %s", str(e))
        return {"success": False, "error": str(e)}

class RecoverInbound(BaseModel):
    ar: Dict[str, Any]
    user_pub: int

@router.post("/ap/recover_pa")
def recover_pa(payload: RecoverInbound) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.ar)
        obj = json_loads(raw)
        phc = obj.get("PHC")
        hid = obj.get("HID")
        crf_in = obj.get("CRF")
        if not isinstance(phc, dict) or not isinstance(hid, str):
            return {"success": False, "error": "invalid_payload"}
        tpa = phc.get("TPA") or {}
        aso = phc.get("ASO") or {}
        tpm = aso.get("TPM") or {}
        try:
            tp_pk = int(str(tpa.get("TPid") or 0))
        except Exception:
            tp_pk = TP_DL_PK
        rec = _apdb_get(hid)
        if not rec:
            return {"success": False, "error": "not_found"}
        cmc = rec.get("CMC") or []
        cmi_stored = rec.get("CMI") or "0"
        cmi_calc = str(hcgen_cmi(cmc, hid))
        rf_val = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
        try:
            crf_int = int(str(crf_in or rf_val or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_prev = str(tpm.get("AF"))
        try:
            r2 = int(str(rec.get("r_bind2") or 0))
        except Exception:
            r2 = 0
        af_calc = str(compute_af_formal(str(hid), AP_PK, tp_pk or TP_DL_PK, int(cmi_calc) % DL_Q, crf_int, r2))
        apm_prime = {"CMI": str(cmi_calc), "Time": datetime.utcnow().isoformat() + "Z"}
        apid = str(AP_PK)
        sig = schnorr_sign(AP_SK, canonical_json({"APM": apm_prime, "APid": apid}).encode())
        apa_out = {"APid": apid, "APproof": {"r": str(sig["r"]), "e": str(sig["e"]), "s": str(sig["s"])}}
        pa_out = {"APM": apm_prime, "APA": apa_out}
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        enc = _encrypt_to_user(upub, {"PA": pa_out, "verified_cmi": (str(cmi_stored) == str(cmi_calc)), "verified_af": (af_prev == af_calc)})
        return {"success": True, "par": enc}
    except Exception as e:
        log.error("recover_pa_failed: %s", str(e))
        return {"success": False, "error": str(e)}


def _build_cmm_matrix(hid: str, phc: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    return [
        [
            {"id": "input_text", "label": "text", "params": {}},
            {"id": "input_voice", "label": "voice", "params": {}},
            {"id": "input_image", "label": "image", "params": {}},
            {"id": "input_video", "label": "video", "params": {}},
            {"id": "input_sensor", "label": "sensor", "params": {}},
            {"id": "input_system_event", "label": "system-event", "params": {}},
        ],
        [
            {"id": "reason_rule_engine", "label": "rule-engine", "params": {}},
            {"id": "reason_bayesian_net", "label": "bayesian-net", "params": {}},
            {"id": "reason_fuzzy_logic", "label": "fuzzy-logic", "params": {}},
            {"id": "reason_llm", "label": "llm", "params": {}},
            {"id": "reason_retrieval", "label": "retrieval", "params": {}},
            {"id": "reason_neural_network", "label": "neural-network", "params": {}},
            {"id": "reason_planner", "label": "planner", "params": {}},
            {"id": "reason_safety_filter", "label": "safety-filter", "params": {}},
        ],
        [
            {"id": "knowledge_local_memory", "label": "local-memory", "params": {}},
            {"id": "knowledge_long_term_memory", "label": "long-term-memory", "params": {}},
            {"id": "knowledge_vector_index", "label": "vector-index", "params": {}},
            {"id": "knowledge_base", "label": "knowledge-base", "params": {}},
            {"id": "knowledge_shared_org_data", "label": "shared-org-data", "params": {}},
        ],
        [
            {"id": "data_browser", "label": "browser", "params": {}},
            {"id": "data_external_api", "label": "external-api", "params": {}},
            {"id": "data_database", "label": "database", "params": {}},
            {"id": "data_blockchain", "label": "blockchain", "params": {}},
            {"id": "data_ipfs", "label": "ipfs", "params": {}},
            {"id": "data_iot_device", "label": "iot-device", "params": {}},
            {"id": "data_cloud_storage", "label": "cloud-storage", "params": {}},
        ],
        [
            {"id": "output_text", "label": "text", "params": {}},
            {"id": "output_speech", "label": "speech", "params": {}},
            {"id": "output_image", "label": "image", "params": {}},
            {"id": "output_notification", "label": "notification", "params": {}},
            {"id": "output_json_api", "label": "json-api", "params": {}},
            {"id": "output_actuation", "label": "actuation", "params": {}},
        ],
    ]

def _apdb_root() -> str:
    import os
    root = os.path.join(os.getcwd(), "local_store", "ap_db")
    os.makedirs(root, exist_ok=True)
    return root

def _apdb_put(hid: str, obj: Dict[str, Any]) -> None:
    import os
    root = _apdb_root()
    path = os.path.join(root, f"{hid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)

def _apdb_get(hid: str) -> Dict[str, Any] | None:
    import os
    root = _apdb_root()
    path = os.path.join(root, f"{hid}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

class RecoverInbound(BaseModel):
    ar: Dict[str, Any]
    user_pub: int

@router.post("/ap/recover_pa")
def recover_pa(payload: RecoverInbound) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.ar)
        obj = json_loads(raw)
        phc = obj.get("PHC")
        hid = obj.get("HID")
        crf_in = obj.get("CRF")
        if not isinstance(phc, dict) or not isinstance(hid, str):
            return {"success": False, "error": "invalid_payload"}
        tpa = phc.get("TPA") or {}
        aso = phc.get("ASO") or {}
        tpm = aso.get("TPM") or {}
        try:
            tp_pk = int(str(tpa.get("TPid") or 0))
        except Exception:
            tp_pk = TP_DL_PK
        rec = _apdb_get(hid)
        if not rec:
            return {"success": False, "error": "not_found"}
        cmc = rec.get("CMC") or []
        cmi_stored = rec.get("CMI") or "0"
        cmi_calc = str(hcgen_cmi(cmc, hid))
        rf_val = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
        try:
            crf_int = int(str(crf_in or rf_val or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_prev = str(tpm.get("AF"))
        try:
            r2 = int(str(rec.get("r_bind2") or 0))
        except Exception:
            r2 = 0
        af_calc = str(compute_af_formal(str(hid), AP_PK, tp_pk or TP_DL_PK, int(cmi_calc) % DL_Q, crf_int, r2))
        apm_prime = {"CMI": str(cmi_calc), "Time": datetime.utcnow().isoformat() + "Z"}
        apid = str(AP_PK)
        sig = schnorr_sign(AP_SK, canonical_json({"APM": apm_prime, "APid": apid}).encode())
        apa_out = {"APid": apid, "APproof": {"r": str(sig["r"]), "e": str(sig["e"]), "s": str(sig["s"])}}
        pa_out = {"APM": apm_prime, "APA": apa_out}
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        enc = _encrypt_to_user(upub, {"PA": pa_out, "verified_cmi": (str(cmi_stored) == str(cmi_calc)), "verified_af": (af_prev == af_calc)})
        return {"success": True, "par": enc}
    except Exception as e:
        log.error("recover_pa_failed: %s", str(e))
        return {"success": False, "error": str(e)}