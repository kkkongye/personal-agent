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
    generate_chameleon_hash,
    sign_with_secret,
    get_tp_rsa_public_pem,
    rsa_decrypt_base64,
    ed25519_verify,
)
import base64
import json
import logging
from pydantic import BaseModel

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
    cr: str
    user_pub: str
    sig: str


# Create a simple in-memory keypair for TP (demo only)
TP_PAILLIER = generate_paillier_keypair()


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
    """Return TP public keys needed by clients (currently only RSA for encryption)."""
    return {"tp_encrypt_pk": get_tp_rsa_public_pem()}


@router.post("/tp/issue_phc_secure")
def issue_phc_secure(payload: SecureInbound) -> Dict[str, Any]:
    """Secure issuance path with encrypted request and user signature.

    Steps:
      1. RSA-OAEP decrypt 'cr' -> plaintext JSON {AF, CMI?, cdid?, ecid?, r_bind_b64, timestamp}
      2. Base64 decode r_bind and user_pub, sig
      3. Verify Ed25519 signature over raw r_bind
      4. Build PHC using AF (and optional fields) similar to legacy path
    """
    try:
        decrypted = rsa_decrypt_base64(payload.cr)
        pt = json.loads(decrypted.decode())
    except Exception as e:
        log.warning("secure decrypt/parse failed: %s", e)
        raise HTTPException(status_code=400, detail="decrypt_failed")

    if "r_bind_b64" not in pt:
        raise HTTPException(status_code=400, detail="missing r_bind_b64")
    try:
        r_bind = base64.b64decode(pt["r_bind_b64"])  # noqa: F841 (reserved for future binding usage)
        user_pub_bytes = base64.b64decode(payload.user_pub)
        sig_bytes = base64.b64decode(payload.sig)
    except Exception:
        raise HTTPException(status_code=400, detail="base64_decode_error")

    if not ed25519_verify(user_pub_bytes, r_bind, sig_bytes):
        raise HTTPException(status_code=400, detail="signature_verification_failed")

    af_value = pt.get("AF")
    # If AF looks like base64 of 32-byte digest, convert back to hex for PHC consistency
    if isinstance(af_value, str):
        try:
            raw = base64.b64decode(af_value)
            if len(raw) == 32:  # sha256 digest length
                af_value = raw.hex()
        except Exception:
            pass  # keep original
    cmi_value = pt.get("CMI")
    cdid_value = pt.get("CDID") or pt.get("cdid") or "cdid:placeholder"
    ecid_value = pt.get("ECID") or pt.get("ecid") or "g"

    if not af_value:
        raise HTTPException(status_code=400, detail="missing_AF")
    if not cmi_value:
        # Allow issuance without CMI (could be added later); fall back to placeholder
        cmi_value = "cmi:placeholder"

    from datetime import datetime
    tpm = {
        "Time": datetime.utcnow().isoformat() + "Z",
        "CDID": cdid_value,
        "AF": af_value,
        "ECID": ecid_value,
    }
    apm = {"Time": datetime.utcnow().isoformat() + "Z", "CMI": cmi_value}

    aso_built = {"TPM": tpm, "APM": apm}

    tpid = "tp.example"
    tpproof = sign_with_secret(TP_PAILLIER.private["lambda"], {"TPM": tpm, "TPid": tpid})
    tpa = {"TPid": tpid, "TPproof": tpproof}

    apid = "ap.placeholder"
    ap_secret = "ap_secret_placeholder"
    approof = sign_with_secret(ap_secret, {"APM": apm, "APid": apid})
    apa = {"APid": apid, "APproof": approof}

    phc = build_phc(aso=aso_built, tpa=tpa, apa=apa, tp_secret=TP_PAILLIER.private["lambda"])
    return {"success": True, "phc": phc, "mode": "secure"}


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
