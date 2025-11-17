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
from crypto_lib import (
    canonical_json,
    sha256_hex,
    ch_compute,
    schnorr_sign,
    schnorr_verify,
    DL_Q,
)


def build_phc(
    aso: Dict[str, Any],
    tpa: Dict[str, Any],
    apa: Dict[str, Any],
    tp_sk: int,
    tp_pk: int,
    ap_pk: int,
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

    # Build TPCH/APCH using DL-based chameleon hash
    tpm_tpa = {"TPM": aso.get("TPM", {}), "TPA": tpa}
    apm_apa = {"APM": aso.get("APM", {}), "APA": apa}
    r_tp = secrets.randbelow(DL_Q - 1) + 1
    r_ap = secrets.randbelow(DL_Q - 1) + 1
    tpch = str(ch_compute(tp_pk, tpm_tpa, {}, r_tp))
    apch = str(ch_compute(ap_pk, apm_apa, {}, r_ap))

    # CHproof: Schnorr over canonical({TPCH,APCH}) with TP secret
    ch_concat = canonical_json({"TPCH": tpch, "APCH": apch}).encode()
    ch_sig = schnorr_sign(tp_sk, ch_concat)

    phc["PROOF"] = {
        "TPCH": tpch,
        "APCH": apch,
        "APCH_r": str(r_ap),
        "CHproof": {"r": str(ch_sig["r"]), "e": str(ch_sig["e"]), "s": str(ch_sig["s"])},
        "VM": {
            "TPproof": "Schnorr(ASO.TPM, TPA.TPid)",
            "APproof": "Schnorr(ASO.APM, APA.APid)",
            "CHproof": "Schnorr(TPCH||APCH)",
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

        # Public verification (Schnorr)
        try:
            tp_pk = int(str(tpa["TPid"]))
            ap_pk = int(str(apa["APid"]))
            tp_sig = tpa["TPproof"]
            ap_sig = apa["APproof"]
            ch_sig = proof["CHproof"]
            if not (schnorr_verify(tp_pk, canonical_json({"TPM": tpm, "TPid": tpa["TPid"]}).encode(), {"r": int(tp_sig["r"]), "e": int(tp_sig["e"]), "s": int(tp_sig["s"])}) ):
                return False
            if not (schnorr_verify(ap_pk, canonical_json({"APM": apm, "APid": apa["APid"]}).encode(), {"r": int(ap_sig["r"]), "e": int(ap_sig["e"]), "s": int(ap_sig["s"])}) ):
                return False
            if not (schnorr_verify(tp_pk, canonical_json({"TPCH": proof["TPCH"], "APCH": proof["APCH"]}).encode(), {"r": int(ch_sig["r"]), "e": int(ch_sig["e"]), "s": int(ch_sig["s"])}) ):
                return False
        except Exception:
            return False

        return True
    except Exception:
        return False


def phc_to_json(phc: Dict[str, Any]) -> str:
    return json.dumps(phc, ensure_ascii=False, indent=2)
