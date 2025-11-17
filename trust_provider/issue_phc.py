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
    generate_paillier_keypair,
    paillier_decrypt,
    paillier_encrypt,
    sign_with_secret,
    canonical_json,
    dl_generate_keypair,
    elgamal_decrypt_bytes,
    schnorr_sign,
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
    apid = str(AP_DL_PK)
    approof_sig = schnorr_sign(AP_DL_SK, canonical_json({"APM": apm, "APid": apid}).encode())
    apa = {"APid": apid, "APproof": {"r": str(approof_sig["r"]), "e": str(approof_sig["e"]), "s": str(approof_sig["s"])}}

    # 4) Build PHC with PROOF fields (use formal CH for TPCH/APCH)
    # Attach SCID when available (legacy path uses RF=0)
    phc = build_phc(aso=aso_built, tpa=tpa, apa=apa, tp_sk=TP_DL_SK, tp_pk=TP_DL_PK, ap_pk=AP_DL_PK)
    phc.setdefault("SCID", {"AF": tpm.get("AF"), "RF": scid_rf})

    return {"success": True, "phc": phc}


@router.get("/tp/public_keys")
def get_public_keys() -> Dict[str, Any]:
    return {
        "tp_dlog_pk": str(TP_DL_PK),
        "ap_dlog_pk": str(AP_DL_PK),
        "dl_params": {"p": str(DL_P), "g": str(5)},
        "paillier_pub": {"n": str(TP_PAILLIER.public.get("n")), "g": str(TP_PAILLIER.public.get("g"))},
    }


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

    # Build JSON-LD PHC per spec with initial APM/APA and formal PROOF
    tpm = {"Time": datetime.utcnow().isoformat() + "Z", "CDID": did, "AF": af_recv, "ECID": "g"}
    apm = {"Time": datetime.utcnow().isoformat() + "Z", "CMI": "0"}
    tpid = str(TP_DL_PK)
    apid = str(AP_DL_PK)
    tpproof_sig = schnorr_sign(TP_DL_SK, canonical_json({"TPM": tpm, "TPid": tpid}).encode())
    approof_sig = schnorr_sign(AP_DL_SK, canonical_json({"APM": apm, "APid": apid}).encode())
    tpa = {"TPid": tpid, "TPproof": {"r": str(tpproof_sig["r"]), "e": str(tpproof_sig["e"]), "s": str(tpproof_sig["s"])}}
    apa = {"APid": apid, "APproof": {"r": str(approof_sig["r"]), "e": str(approof_sig["e"]), "s": str(approof_sig["s"])}}
    phc = build_phc(aso={"TPM": tpm, "APM": apm}, tpa=tpa, apa=apa, tp_sk=TP_DL_SK, tp_pk=TP_DL_PK, ap_pk=AP_DL_PK)
    phc["SCID"] = scid
    phc["DID"] = did
    # Store secured info
    s1 = kdf_s1(TP_PAILLIER.private["lambda"], TP_DL_SK, rf)
    secinfo_obj = {"BI": bi, "PII": pii, "DID": did, "r_bind": rb}
    secinfo = sym_encrypt(s1, json.dumps(secinfo_obj, separators=(",", ":")).encode())
    cid = ipfs_put(secinfo)
    phc["CID"] = cid
    phc["CRF"] = crf
    return {"success": True, "phc": phc, "mode": "secure_phc_jsonld"}


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
