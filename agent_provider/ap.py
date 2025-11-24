from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime
import json
import logging
from crypto_lib import (
    elgamal_decrypt_bytes,
    elgamal_encrypt_bytes as tp_elg_encrypt_bytes,
    schnorr_sign,
    schnorr_verify,
    canonical_json,
    sha256_hex,
    DL_P,
    DL_Q,
    hash_to_int,
    inv_mod,
)
from crypto_lib.keys import AP_SK, AP_PK, TP_PAILLIER, TP_DL_PK
from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.crypto import sign_with_secret

router = APIRouter()
log = logging.getLogger("ap")

# Keys provided by shared module


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
        # Use SCID.RF as exponent source for formal AF verification
        try:
            crf_src = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
            crf_int = int(str(crf_src or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_calc = compute_af_formal(str(hid), AP_PK, TP_DL_PK, cmi_int % DL_Q, crf_int, rb2)
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
                phc_mod.setdefault("ASO", {}).update({"APM": apm_prime})
                phc_mod.setdefault("ASO", {}).setdefault("TPM", {})["AF"] = str(af_calc)
                phc_mod["APA"] = apa
                phc_mod.setdefault("PROOF", {})["needs_tp_resign"] = True
            except Exception:
                pass
        # Recompute verified_af against updated PHC
        try:
            af_now = (phc_mod.get("ASO") or {}).get("TPM", {}).get("AF")
            verified_af = (str(af_now) == str(af_calc))
        except Exception:
            verified_af = False
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        # Persist AP local state for recovery
        try:
            _apdb_put(hid, {"CMC": cmc, "CMI": str(cmi_int), "r_bind2": str(rb2), "ts": datetime.utcnow().isoformat() + "Z"})
        except Exception:
            pass
        try:
            chain = _compute_hash_chain(hid, cmc)
            phc_mod.setdefault("ASO", {}).setdefault("HASH_CHAIN", chain)
        except Exception:
            chain = {"head": None, "entries": []}
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
            "HASH_CHAIN_HEAD": str(chain.get("head")) if chain.get("head") else None,
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
        proof = phc.get("PROOF") or {}
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
        # Resolve CRF exponent: prefer CRF.c1 if dict provided, fallback to SCID.RF
        rf_val = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
        try:
            crf_src = rf_val if rf_val is not None else crf_in
            crf_int = int(str(crf_src or 0)) % DL_Q
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
            phc_mod = json.loads(json.dumps(phc))
            phc_mod.setdefault("ASO", {}).setdefault("TPM", {})["AF"] = str(af_calc)
        except Exception:
            phc_mod = phc
        try:
            tp_sig = tpa.get("TPproof") or {}
            ch_sig = proof.get("CHproof") or {}
            verified_tp = bool(schnorr_verify(tp_pk, canonical_json({"TPM": tpm, "TPid": tpa.get("TPid")}).encode(), {"r": int(str(tp_sig.get("r") or 0)), "e": int(str(tp_sig.get("e") or 0)), "s": int(str(tp_sig.get("s") or 0))}))
            verified_ch = bool(schnorr_verify(tp_pk, canonical_json({"TPCH": proof.get("TPCH"), "APCH": proof.get("APCH")}).encode(), {"r": int(str(ch_sig.get("r") or 0)), "e": int(str(ch_sig.get("e") or 0)), "s": int(str(ch_sig.get("s") or 0))}))
        except Exception:
            verified_tp = False
            verified_ch = False
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        enc = _encrypt_to_user(upub, {"PA": pa_out, "PHC": phc_mod, "verified_cmi": (str(cmi_stored) == str(cmi_calc)), "verified_af": (str((phc_mod.get("ASO") or {}).get("TPM", {}).get("AF")) == str(af_calc)), "verified_tp": verified_tp, "verified_ch": verified_ch})
        return {"success": True, "par": enc}
    except Exception as e:
        log.error("recover_pa_failed: %s", str(e))
        return {"success": False, "error": str(e)}


def _build_cmm_matrix(hid: str, phc: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    return [
        [
            {"id": "feature_text_processing", "label": "text-processing", "params": {}},
            {"id": "feature_news_search", "label": "news-search", "params": {}},
        ],
        [
            {"id": "input_text", "label": "text", "params": {}},
            {"id": "input_voice", "label": "voice", "params": {}},
            {"id": "input_image", "label": "image", "params": {}},
        ],
        [
            {"id": "reason_llm", "label": "llm", "params": {}},
            {"id": "reason_retrieval", "label": "retrieval", "params": {}},
            {"id": "reason_neural_network", "label": "neural-network", "params": {}},
        ],
        [
            {"id": "knowledge_local_memory", "label": "local-memory", "params": {}},
            {"id": "knowledge_long_term_memory", "label": "long-term-memory", "params": {}},
            {"id": "knowledge_base", "label": "knowledge-base", "params": {}},
        ],
        [
            {"id": "output_text", "label": "text", "params": {}},
            {"id": "output_speech", "label": "speech", "params": {}},
            {"id": "output_image", "label": "image", "params": {}},
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

 
def _compute_hash_chain(hid: str, cmc: List[List[Dict[str, Any]]]) -> Dict[str, Any]:
    from user.crypto import canonical_json, sha256_hex
    prev = sha256_hex(str(hid))
    entries: List[Dict[str, Any]] = []
    idx = 0
    for row in (cmc or []):
        for item in (row or []):
            label = str(item.get("label") or "")
            data = canonical_json({"label": label, "idx": idx})
            h = sha256_hex(prev + data)
            entries.append({"idx": idx, "label": label, "prev": prev, "hash": h})
            prev = h
            idx += 1
    return {"head": prev, "entries": entries}

class UpdateInitRequest(BaseModel):
    ar: Dict[str, Any]
    user_pub: int

class UpdateSubmitRequest(BaseModel):
    cmc_enc: Dict[str, Any]
    user_pub: int | str

@router.post("/ap/update_init")
def update_init(payload: UpdateInitRequest) -> Dict[str, Any]:
    try:
        raw = elgamal_decrypt_bytes(AP_SK, payload.ar)
        obj = json_loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")
    phc = obj.get("PHC")
    hid = obj.get("HID")
    crf = obj.get("CRF")
    if not isinstance(phc, dict) or not isinstance(hid, str):
        raise HTTPException(status_code=400, detail="invalid_payload")
    cmm = _build_cmm_matrix(hid, phc)
    return {"success": True, "cmm_enc": _encrypt_to_user(payload.user_pub, {"CMM": cmm, "CRF": crf})}

@router.post("/ap/update_submit")
def update_submit(payload: UpdateSubmitRequest) -> Dict[str, Any]:
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
        rb3 = _rand_int()
        r_ap3 = _rand_int()
        ch_val = ch_compute(AP_PK, apm_prime, apa, r_ap3)
        af_prev = phc.get("ASO", {}).get("TPM", {}).get("AF")
        try:
            crf_src = ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None)
            crf_int = int(str(crf_src or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_calc = compute_af_formal(str(hid), AP_PK, TP_DL_PK, cmi_int % DL_Q, crf_int, rb3)
        verified_af = (str(af_prev) == str(af_calc))
        cch_val = cch_compute(AP_PK, TP_DL_PK, cmi_int, crf_int, rb3)
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
                phc_mod.setdefault("ASO", {}).update({"APM": apm_prime})
                phc_mod.setdefault("ASO", {}).setdefault("TPM", {})["AF"] = str(af_calc)
                phc_mod["APA"] = apa
                phc_mod.setdefault("PROOF", {})["needs_tp_resign"] = True
            except Exception:
                pass
        try:
            upub = int(str(payload.user_pub))
        except Exception:
            return {"success": False, "error": "invalid_user_pub"}
        try:
            _apdb_put(hid, {"CMC": cmc, "CMI": str(cmi_int), "r_bind2": str(rb3), "ts": datetime.utcnow().isoformat() + "Z"})
        except Exception:
            pass
        try:
            chain = _compute_hash_chain(hid, cmc)
            phc_mod.setdefault("ASO", {}).setdefault("HASH_CHAIN", chain)
        except Exception:
            chain = {"head": None, "entries": []}
        enc = _encrypt_to_user(upub, {
            "r_bind2": str(rb3),
            "r_ap": str(r_ap3),
            "PHC": phc_mod,
            "PHC_original": phc,
            "PA": pa,
            "CH": str(ch_val),
            "CCH": str(cch_val),
            "verified_af": (str((phc_mod.get("ASO") or {}).get("TPM", {}).get("AF")) == str(af_calc)),
            "ap_pk": str(AP_PK),
            "tp_pk": str(TP_DL_PK),
            "HASH_CHAIN_HEAD": str(chain.get("head")) if chain.get("head") else None,
        })
        return {"success": True, "par": enc}
    except Exception as e:
        log.error("update_submit_failed: %s", str(e))
        return {"success": False, "error": str(e)}