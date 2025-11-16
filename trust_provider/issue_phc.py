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
from .crypto import (
    generate_paillier_keypair,
    paillier_decrypt,
    paillier_encrypt,
    sign_with_secret,
    dl_generate_keypair,
    elgamal_decrypt_bytes,
    schnorr_verify,
    compute_af,
    kdf_s1,
    sym_encrypt,
    cch_hash,
    DL_P,
    ipfs_put,
    crf_encrypt,
)
import base64
import json
import logging
from pydantic import BaseModel
import hashlib
import secrets

log = logging.getLogger("tp")

router = APIRouter()


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


class SecureInbound(BaseModel):
    cr: Dict[str, Any]
    user_pub: int
    sig: Dict[str, int]


# Create a simple in-memory keypair for TP (demo only)
TP_PAILLIER = generate_paillier_keypair()
TP_DL_SK, TP_DL_PK = dl_generate_keypair()
AP_DL_SK, AP_DL_PK = dl_generate_keypair()


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
        tpm = {
            "Time": datetime.utcnow().isoformat() + "Z",
            "CDID": aso.cdid or "cdid:placeholder",
            "AF": aso.af,
            "ECID": aso.ecid or "g",
        }
        apm = {
            "Time": datetime.utcnow().isoformat() + "Z",
            "CMI": aso.cmi,
        }

    aso_built = {"TPM": tpm, "APM": apm}

    # 2) TPA: choose TPid (use a deterministic id derived from public key stub)
    tpid = "tp.example"
    tpproof = sign_with_secret(TP_PAILLIER.private["lambda"], {"TPM": tpm, "TPid": tpid})
    tpa = {"TPid": tpid, "TPproof": tpproof}

    # 3) APA (placeholder): APproof is a stub signature with a fixed secret
    apid = "ap.placeholder"
    ap_secret = "ap_secret_placeholder"
    approof = sign_with_secret(ap_secret, {"APM": apm, "APid": apid})
    apa = {"APid": apid, "APproof": approof}

    # 4) Build PHC with PROOF fields
    phc = build_phc(aso=aso_built, tpa=tpa, apa=apa, tp_secret=TP_PAILLIER.private["lambda"])

    return {"success": True, "phc": phc}


@router.get("/tp/public_keys")
def get_public_keys() -> Dict[str, Any]:
    return {"tp_dlog_pk": TP_DL_PK, "ap_dlog_pk": AP_DL_PK, "dl_params": {"p": DL_P, "g": 5}, "paillier_pub": TP_PAILLIER.public}


@router.post("/tp/issue_phc_secure")
def issue_phc_secure(payload: SecureInbound) -> Dict[str, Any]:
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
        raise HTTPException(status_code=400, detail="af_mismatch")

    rf = paillier_encrypt(TP_PAILLIER.public, int(hashlib.sha256(str(idv).encode()).hexdigest(), 16))
    crf = crf_encrypt(TP_DL_PK, rf, rb)
    scid = {"AF": af_recv, "RF": rf}
    did = f"did:wba:{hashlib.sha256(json.dumps(scid, separators=(",", ":")).encode()).hexdigest()}:example"
    rtp = secrets.randbelow(DL_P - 2) + 1
    s1 = kdf_s1(TP_PAILLIER.private["lambda"], TP_DL_SK, rf)
    secinfo_obj = {"BI": bi, "PII": pii, "DID": did, "r_bind": rb, "r_tp": rtp}
    secinfo = sym_encrypt(s1, json.dumps(secinfo_obj, separators=(",", ":")).encode())
    cid = ipfs_put(secinfo)
    cch = cch_hash(TP_DL_SK, af_recv, crf, rtp)
    ecid = paillier_encrypt(TP_PAILLIER.public, int(hashlib.sha256((cid + str(rf)).encode()).hexdigest(), 16))
    return {"success": True, "phc": {"SCID": scid, "DID": did, "CID": cid, "ECID": ecid, "CCH": cch, "CRF": crf, "Secinfo": secinfo}, "mode": "secure_dl"}


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
