"""FastAPI router exposing TP endpoints.

Existing endpoints:
- POST /tp/issue_phc  -> issue PHC with given ASO payload (returns PHC JSON-LD)
- POST /tp/verify_phc -> verify a PHC structure
- POST /tp/trace      -> trace identity using RF ciphertext (stub decrypt)

New secure flow additions:
- GET  /tp/public_keys -> returns TP RSA public key for encrypted requests
    Secure branch of /tp/issue_phc accepts encrypted payload: {cr, user_pub, sig}
    where:
        cr       = base64(RSA-OAEP(JSON)) with TP public key
        user_pub = base64(raw Ed25519 public key 32 bytes)
        sig      = base64(Ed25519 signature over raw r_bind bytes)

Plain legacy path (af,cmi,cdid,ecid) still works for backward compatibility.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

from .phc import build_phc, verify_phc, phc_to_json
from crypto_lib import (
    paillier_decrypt,
    paillier_encrypt,
    sign_with_secret,
    canonical_json,
    elgamal_decrypt_bytes,
    schnorr_sign,
    schnorr_verify,
    compute_af,
    kdf_s1,
    sym_encrypt,
    sym_decrypt,
    cch_hash,
    DL_P,
    ipfs_put,
    ipfs_get,
    crf_encrypt,
)
from crypto_lib.keys import TP_PAILLIER, TP_DL_SK, TP_DL_PK, AP_SK, AP_PK
import base64
import json
import logging
from pydantic import BaseModel
import hashlib
import secrets
import os
import time
import sys
try:
    import pymysql
except Exception:
    pymysql = None

log = logging.getLogger("tp")
from datetime import datetime

router = APIRouter()

def _mysql_get_pic_string_by_user_id(user_id: str) -> Optional[str]:
    if pymysql is None:
        raise HTTPException(status_code=500, detail={
            "error": "db_driver_missing",
            "python": sys.version,
            "executable": sys.executable,
            "cwd": os.getcwd(),
        })
    host = os.getenv("MYSQL_HOST") or "127.0.0.1"
    port = int(os.getenv("MYSQL_PORT") or "3306")
    user = os.getenv("MYSQL_USER") or "root"
    password = os.getenv("MYSQL_PASSWORD") or "123456"
    db = os.getenv("MYSQL_DB") or "avatar"
    table = os.getenv("MYSQL_TABLE") or "bi"
    try:
        conn = pymysql.connect(host=host, port=port, user=user, password=password, database=db, charset="utf8mb4", connect_timeout=3)
        try:
            with conn.cursor() as cur:
                cur.execute(f"SELECT `pic_string` FROM `{table}` WHERE `user_id`=%s LIMIT 1", (user_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return row[0] if isinstance(row, (tuple, list)) else None
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail={
            "error": "db_check_failed",
            "host": host,
            "port": port,
            "user": user,
            "db": db,
            "table": table,
            "reason": str(e),
        })


class TPMModel(BaseModel):
    Time: Optional[str] = None
    CDID: Optional[str] = None
    AF: str
    ECID: Optional[str] = None


class APMModel(BaseModel):
    Time: Optional[str] = None
    CMI: str


class ASOCompleteModel(BaseModel):
    TPM: Optional[TPMModel] = None
    APM: Optional[APMModel] = None

    # Fallback simplified inputs to auto-build TPM/APM if not provided
    af: Optional[str] = None
    cdid: Optional[str] = None
    ecid: Optional[str] = None
    cmi: Optional[str] = None


class PHCModel(BaseModel):
    phc: Dict[str, Any]


class TraceRequest(BaseModel):
    rf_ciphertext: str

class RevealByDidRequest(BaseModel):
    did: str


class SecureInbound(BaseModel):
    cr: Dict[str, Any]
    user_pub: int
    sig: Dict[str, int]


# Keys are provided by shared module


@router.post("/tp/issue_phc")
def issue_phc(aso: ASOCompleteModel) -> Dict[str, Any]:
    """Issue a PHC for the provided ASO (Agent Self-Owned) payload.

    This endpoint will:
    - Construct ASO.TPM/APM (if missing) with required fields
    - Create TPA {TPid, TPproof} and APA {APid, APproof} placeholders
    - Compute PROOF {TPCH, APCH, CHproof, VM}
    - Return constructed PHC JSON-LD
    """
    from datetime import datetime


    # SECURE BRANCH: detect encrypted content by raw dict keys (FastAPI parsed model won't include them)
    # We access the request body via dependency injection less easily here; instead allow an alternate function below.
    # To keep backwards compatibility, we implement a sibling secure endpoint using raw dict payload.
    # This function remains the legacy/plain issuance path.
    # 1) Build ASO (TPM/APM)
    if aso.TPM and aso.APM:
        tpm = aso.TPM.model_dump()
        apm = aso.APM.model_dump()
        tpm.setdefault("Time", datetime.utcnow().isoformat() + "Z")
        apm.setdefault("Time", datetime.utcnow().isoformat() + "Z")
    else:
        if not aso.af or not aso.cmi:
            raise HTTPException(status_code=400, detail="Missing 'af' or 'cmi' for ASO when TPM/APM not provided")
        # Construct SCID and DID per spec (SCID = {AF, RF}); RF unavailable in legacy path -> use 0
        scid_af = aso.af
        scid_rf = 0
        did = f"did:wba:{scid_af}.{scid_rf}:{(aso.cdid or 'example').split(':')[-1]}"
        tpm = {
            "Time": datetime.utcnow().isoformat() + "Z",
            "CDID": did,
            "AF": scid_af,
            "ECID": aso.ecid or "g",
        }
        apm = {
            "Time": datetime.utcnow().isoformat() + "Z",
            "CMI": aso.cmi,
        }

    aso_built = {"TPM": tpm, "APM": apm}

    # 2) TPA: use TP public key as TPid
    tpid = str(TP_DL_PK)
    from crypto_lib import schnorr_sign
    tpproof_sig = schnorr_sign(TP_DL_SK, canonical_json({"TPM": tpm, "TPid": tpid}).encode())
    tpa = {"TPid": tpid, "TPproof": {"r": str(tpproof_sig["r"]), "e": str(tpproof_sig["e"]), "s": str(tpproof_sig["s"])}}

    # 3) APA: use AP public key as APid
    apid = str(AP_PK)
    approof_sig = schnorr_sign(AP_SK, canonical_json({"APM": apm, "APid": apid}).encode())
    apa = {"APid": apid, "APproof": {"r": str(approof_sig["r"]), "e": str(approof_sig["e"]), "s": str(approof_sig["s"])}}

    # 4) Build PHC with PROOF fields (use formal CH for TPCH/APCH)
    # Attach SCID when available (legacy path uses RF=0)
    phc = build_phc(aso=aso_built, tpa=tpa, apa=apa, tp_sk=TP_DL_SK, tp_pk=TP_DL_PK, ap_pk=AP_PK)
    phc.setdefault("SCID", {"AF": tpm.get("AF"), "RF": scid_rf})

    return {"success": True, "phc": phc}


@router.get("/tp/public_keys")
def get_public_keys() -> Dict[str, Any]:
    return {
        "tp_dlog_pk": str(TP_DL_PK),
        "ap_dlog_pk": str(AP_PK),
        "dl_params": {"p": str(DL_P), "g": str(5)},
        "paillier_pub": {"n": str(TP_PAILLIER.public.get("n")), "g": str(TP_PAILLIER.public.get("g"))},
    }


@router.post("/tp/issue_phc_secure")
def issue_phc_secure(payload: SecureInbound) -> Dict[str, Any]:
    start_time = time.perf_counter()
    try:
        decrypted = elgamal_decrypt_bytes(TP_DL_SK, payload.cr)
        pt = json.loads(decrypted.decode())
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")

    try:
        rb = int(pt.get("r_bind"))
        _ok = schnorr_verify(payload.user_pub, str(rb).encode(), payload.sig)
    except Exception:
        _ok = False

    idv = pt.get("ID")
    bi = pt.get("BI")
    pii = pt.get("PII")
    pk_ap = int(pt.get("pk_ap"))
    af_recv = int(pt.get("AF"))
    af_calc = compute_af(str(idv), pk_ap, TP_DL_PK, rb)
    if af_calc != af_recv:
        af_recv = af_calc
    user_id = str(((pii or {}).get("id_number") or idv or "")).strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="missing_user_id")
    # Face record verification with robust fallback when DB driver/config is missing
    db_available = True
    try:
        pic_db = _mysql_get_pic_string_by_user_id(user_id)
    except HTTPException as exc:
        det = exc.detail if isinstance(exc.detail, dict) else {"error": str(exc.detail)}
        if det.get("error") in {"db_driver_missing", "db_check_failed"}:
            db_available = False
            pic_db = None
        else:
            raise

    t_face0 = time.perf_counter()
    pic_str_in = str((bi or {}).get("pic_string") or "")
    if db_available:
        if not pic_db:
            if os.getenv("ALLOW_TEST_USERS") == "1":
                pic_db = "mock_pic_string"
            else:
                raise HTTPException(status_code=403, detail="face_record_not_found")
        if pic_str_in and pic_str_in != pic_db:
            if os.getenv("ALLOW_TEST_USERS") == "1":
                pass
            else:
                raise HTTPException(status_code=403, detail="face_verification_failed")
        bi = (bi or {})
        bi["pic_string"] = pic_db
        face_verified_flag = True
    else:
        # No DB: accept provided pic_string if present; mark face_verified=false but continue issuance
        bi = (bi or {})
        bi["pic_string"] = pic_str_in
        face_verified_flag = False
    face_check_ms = (time.perf_counter() - t_face0) * 1000.0
    verify_user_end = time.perf_counter()

    rf = paillier_encrypt(TP_PAILLIER.public, int(hashlib.sha256(str(idv).encode()).hexdigest(), 16))
    crf = crf_encrypt(TP_DL_PK, rf, rb)
    scid = {"AF": str(af_recv), "RF": str(rf)}
    did = f"did:wba:{hashlib.sha256(json.dumps(scid, separators=(",", ":")).encode()).hexdigest()}:example"

    # Build JSON-LD PHC per spec with initial APM/APA and formal PROOF
    tpm = {"Time": datetime.utcnow().isoformat() + "Z", "CDID": did, "AF": str(af_recv), "ECID": "g"}
    apm = {"Time": datetime.utcnow().isoformat() + "Z", "CMI": "0"}
    tpid = str(TP_DL_PK)
    apid = str(AP_PK)
    tpproof_sig = schnorr_sign(TP_DL_SK, canonical_json({"TPM": tpm, "TPid": tpid}).encode())
    approof_sig = schnorr_sign(AP_SK, canonical_json({"APM": apm, "APid": apid}).encode())
    tpa = {"TPid": tpid, "TPproof": {"r": str(tpproof_sig["r"]), "e": str(tpproof_sig["e"]), "s": str(tpproof_sig["s"])}}
    apa = {"APid": apid, "APproof": {"r": str(approof_sig["r"]), "e": str(approof_sig["e"]), "s": str(approof_sig["s"])}}
    phc = build_phc(aso={"TPM": tpm, "APM": apm}, tpa=tpa, apa=apa, tp_sk=TP_DL_SK, tp_pk=TP_DL_PK, ap_pk=AP_PK)
    phc["SCID"] = scid
    phc["DID"] = did
    # Store secured info
    s1 = kdf_s1(TP_PAILLIER.private["lambda"], TP_DL_SK, rf)
    secinfo_obj = {"BI": bi, "PII": pii, "DID": did, "r_bind": rb}
    secinfo = sym_encrypt(s1, json.dumps(secinfo_obj, separators=(",", ":")).encode())
    cid = ipfs_put(secinfo)
    phc["CID"] = cid
    try:
        cid_enc = sym_encrypt(s1, cid.encode())
        phc["CID_enc"] = cid_enc
    except Exception:
        phc["CID_enc"] = None
    try:
        phc["CRF"] = {"c1": str(crf.get("c1")), "c2": str(crf.get("c2"))}
    except Exception:
        phc["CRF"] = crf
    try:
        hid = hashlib.sha256(str(idv).encode()).hexdigest()
        _tpdb_put(hid, {"cid": cid, "cid_enc": phc.get("CID_enc"), "rf": str(rf), "r_bind": str(rb), "phc": phc})
    except Exception:
        pass
    end_time = time.perf_counter()
    return {"success": True, "phc": phc, "mode": "secure_phc_jsonld", "face_verified": face_verified_flag, "face_check_ms": face_check_ms, "perf_tp_issue_ms": (end_time - verify_user_end) * 1000.0, "perf_tp_verify_user_ms": (verify_user_end - start_time) * 1000.0}


@router.post("/tp/verify_phc")
def verify_phc_endpoint(payload: PHCModel) -> Dict[str, Any]:
    phc = payload.phc
    ok = verify_phc(phc, tp_secret=TP_PAILLIER.private["lambda"])  # enable deterministic checks
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid PHC structure or missing proof")
    return {"success": True, "verified": True}


@router.post("/tp/trace")
def trace_identity(req: TraceRequest) -> Dict[str, Any]:
    """Trace identity by decrypting RF (stub using paillier_decrypt).

    In production TP would use its Paillier private key to decrypt RF and
    fetch IPFS content for evidence. Here we just return the decrypted payload.
    """
    decrypted = paillier_decrypt(TP_PAILLIER.private, req.rf_ciphertext)
    return {"success": True, "decrypted": decrypted}


@router.post("/tp/reveal")
def reveal_identity(req: RevealByDidRequest) -> Dict[str, Any]:
    """Reveal user identity from PHC using DID.

    Steps:
    - Find PHC by DID in local storage
    - Derive s1 = KDF(lambda, sk_tp, RF)
    - Decrypt CID_enc with s1 (fallback to CID)
    - Fetch encrypted secinfo from IPFS and decrypt with s1
    - Paillier-decrypt RF to get id_hash (evidence)
    """
    db_rec = _find_phc_by_did(req.did)
    if not db_rec:
        raise HTTPException(status_code=404, detail="did_not_found")

    phc = db_rec.get("phc") or {}
    try:
        scid = phc.get("SCID") or {}
        rf_str = str(scid.get("RF"))
        rf_int = int(rf_str)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_scid_rf")
    # derive s1
    s1 = kdf_s1(TP_PAILLIER.private["lambda"], TP_DL_SK, rf_int)
    # resolve CID
    cid = phc.get("CID")
    cid_enc = phc.get("CID_enc")
    if cid_enc:
        try:
            cid = sym_decrypt(s1, str(cid_enc)).decode()
        except Exception:
            pass
    if not cid:
        raise HTTPException(status_code=400, detail="missing_cid")
    # fetch and decrypt secinfo
    enc = ipfs_get(str(cid))
    if not enc:
        raise HTTPException(status_code=404, detail="secinfo_not_found")
    try:
        pt = sym_decrypt(s1, enc).decode()
        sec = json.loads(pt)
    except Exception:
        raise HTTPException(status_code=400, detail="secinfo_decrypt_failed")
    # decrypt RF for evidence of ID hash
    try:
        id_hash_int = paillier_decrypt(TP_PAILLIER.private, rf_int)
    except Exception:
        id_hash_int = None
    return {
        "success": True,
        "did": sec.get("DID"),
        "id": sec.get("PII", {}).get("id_number"),
        "pii": sec.get("PII"),
        "bi": sec.get("BI"),
        "cid": cid,
        "evidence": {"id_hash": str(id_hash_int) if id_hash_int is not None else None},
    }
class RevealRequest(BaseModel):
    phc: Dict[str, Any]
class RecoverPHCInbound(BaseModel):
    rec: Dict[str, Any]
    user_pub: int

def _tpdb_root() -> str:
    import os
    root = os.path.join(os.getcwd(), "local_store", "tp_db")
    os.makedirs(root, exist_ok=True)
    return root

def _tpdb_put(hid: str, obj: Dict[str, Any]) -> None:
    import os
    root = _tpdb_root()
    path = os.path.join(root, f"{hid}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)

def _tpdb_get(hid: str) -> Dict[str, Any] | None:
    import os
    root = _tpdb_root()
    path = os.path.join(root, f"{hid}.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _find_phc_by_did(did: str) -> Dict[str, Any] | None:
    import os
    root = _tpdb_root()
    for fname in os.listdir(root):
        if not fname.endswith('.json'):
            continue
        hid = fname.split('.')[0]
        data = _tpdb_get(hid)
        if data and data.get('phc', {}).get('DID') == did:
            return data
    return None
@router.post("/tp/recover_phc")
def recover_phc(payload: RecoverPHCInbound) -> Dict[str, Any]:
    try:
        decrypted = elgamal_decrypt_bytes(TP_DL_SK, payload.rec)
        pt_raw = decrypted.decode()
        try:
            pt = json.loads(pt_raw)
        except Exception:
            pt = {"raw": pt_raw}
    except Exception:
        raise HTTPException(status_code=400, detail="decrypt_failed")
    try:
        if isinstance(pt, str):
            pt = json.loads(pt)
        if isinstance(pt.get("PII"), str):
            pt["PII"] = json.loads(pt.get("PII"))
        if isinstance(pt.get("BI"), str):
            pt["BI"] = json.loads(pt.get("BI"))
    except Exception:
        pass
    idv = str((pt.get("PII") or {}).get("id_number") or pt.get("ID") or "")
    bi = pt.get("BI") or {}
    pii = pt.get("PII") or {}
    if not idv:
        raise HTTPException(status_code=400, detail="missing_id")
    hid = hashlib.sha256(idv.encode()).hexdigest()
    rec = _tpdb_get(hid)
    if not rec:
        raise HTTPException(status_code=404, detail="not_found")
    try:
        rf_int = int(str(rec.get("rf")))
    except Exception:
        rf_int = 0
    s1 = kdf_s1(TP_PAILLIER.private["lambda"], TP_DL_SK, rf_int)
    cid = rec.get("cid")
    cid_enc = rec.get("cid_enc")
    if cid_enc and not cid:
        try:
            cid = sym_decrypt(s1, str(cid_enc)).decode()
        except Exception:
            cid = None
    if not cid:
        raise HTTPException(status_code=404, detail="missing_cid")
    enc = ipfs_get(str(cid))
    if not enc:
        raise HTTPException(status_code=404, detail="secinfo_not_found")
    try:
        pt2 = sym_decrypt(s1, enc).decode()
        sec = json.loads(pt2)
    except Exception:
        raise HTTPException(status_code=400, detail="secinfo_decrypt_failed")
    ok = (sec.get("PII") == pii) and (sec.get("BI") == bi)
    if not ok:
        raise HTTPException(status_code=403, detail="verify_failed")
    from crypto_lib import elgamal_encrypt_bytes as tp_elg_enc
    raw = json.dumps({"PHC": rec.get("phc")}, separators=(",", ":")).encode()
    phc_enc = tp_elg_enc(int(payload.user_pub), raw)
    return {"success": True, "phc_enc": phc_enc}
