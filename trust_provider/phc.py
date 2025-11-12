"""PHC (Personhood Credential) helpers aligned to the picture spec.

This module builds a PHC with the exact field names and hierarchy specified:
- ASO: contains TPM(Time, CDID, AF, ECID) and APM(Time, CMI)
- TPA: { TPid, TPproof }
- APA: { APid, APproof }
- PROOF: { TPCH, APCH, CHproof, VM }

All proofs/hashes are stubbed but deterministic for basic verification.
"""
from typing import Dict, Any
from datetime import datetime
import json
import secrets
from .crypto import (
    canonical_json,
    generate_chameleon_hash,
    sign_with_secret,
    verify_with_secret,
)


def build_phc(
    aso: Dict[str, Any],
    tpa: Dict[str, Any],
    apa: Dict[str, Any],
    tp_secret: str,
) -> Dict[str, Any]:
    """Construct a PHC JSON-LD object with required fields and proofs.

    - TPCH = CH((TPM, TPA))
    - APCH = CH((APM, APA))
    - CHproof = Sign_tp( TPCH || APCH )
    - VM lists how to verify TPproof/APproof/CHproof (informational)
    """
    # Ensure ASO has TPM/APM objects
    if not (isinstance(aso, dict) and "TPM" in aso and "APM" in aso):
        raise ValueError("ASO must contain TPM and APM objects")

    phc = {
        "@context": "https://wba.org/phc/v1",
        "id": f"phc:{secrets.token_hex(8)}",
        "issued": datetime.utcnow().isoformat() + "Z",
        "ASO": aso,
        "TPA": tpa,
        "APA": apa,
    }

    # Build TPCH/APCH using chameleon-hash stub
    tpm_tpa = {"TPM": aso.get("TPM", {}), "TPA": tpa}
    apm_apa = {"APM": aso.get("APM", {}), "APA": apa}

    tpch = generate_chameleon_hash(canonical_json(tpm_tpa))["hash"]
    apch = generate_chameleon_hash(canonical_json(apm_apa))["hash"]

    # CHproof: TP signs the concatenation of TPCH || APCH deterministically
    ch_concat = {"TPCH": tpch, "APCH": apch}
    ch_proof = sign_with_secret(tp_secret, ch_concat)

    phc["PROOF"] = {
        "TPCH": tpch,
        "APCH": apch,
        "CHproof": ch_proof,
        "VM": {
            "TPproof": "Sign_tp(ASO.TPM, TPA.TPid)",
            "APproof": "Sign_ap(ASO.APM, APA.APid)",
            "CHproof": "Sign_tp(TPCH||APCH)",
        },
    }

    return phc


def verify_phc(phc: Dict[str, Any], tp_secret: str | None = None) -> bool:
    """Basic structural and consistency checks.

    - Ensure required sections exist: ASO(TPM/APM), TPA(TPid/TPproof), APA(APid/APproof), PROOF(TPCH/APCH/CHproof/VM)
    - If tp_secret provided: verify CHproof = Sign_tp({TPCH,APCH}) deterministically
      and verify TPproof against ASO.TPM+TPid (best-effort stub)
    """
    try:
        # Required top-level
        for r in ("ASO", "TPA", "APA", "PROOF"):
            if r not in phc:
                return False

        aso = phc["ASO"]
        tpa = phc["TPA"]
        apa = phc["APA"]
        proof = phc["PROOF"]

        # ASO.TPM/APM present with required keys
        if not (isinstance(aso, dict) and "TPM" in aso and "APM" in aso):
            return False
        tpm = aso["TPM"]
        apm = aso["APM"]
        for k in ("Time", "CDID", "AF", "ECID"):
            if k not in tpm:
                return False
        for k in ("Time", "CMI"):
            if k not in apm:
                return False

        # TPA/APA fields
        if "TPid" not in tpa or "TPproof" not in tpa:
            return False
        if "APid" not in apa or "APproof" not in apa:
            return False

        # PROOF fields
        for k in ("TPCH", "APCH", "CHproof", "VM"):
            if k not in proof:
                return False

        # Optional deterministic checks
        if tp_secret:
            # CHproof consistency
            expected_ch = sign_with_secret(tp_secret, {"TPCH": proof["TPCH"], "APCH": proof["APCH"]})
            if expected_ch != proof.get("CHproof"):
                return False

            # TPproof best-effort: sign over (ASO.TPM, TPid)
            expected_tp_proof = sign_with_secret(tp_secret, {"TPM": tpm, "TPid": tpa["TPid"]})
            if expected_tp_proof != tpa.get("TPproof"):
                return False

        return True
    except Exception:
        return False


def phc_to_json(phc: Dict[str, Any]) -> str:
    return json.dumps(phc, ensure_ascii=False, indent=2)
