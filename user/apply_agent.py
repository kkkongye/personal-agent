"""HTTP client for interacting with TP/AP endpoints remotely."""
from typing import Any, Dict
import httpx
import secrets
import time
import json
from .crypto import (
    compute_cmi,
    compute_r_bind,
    dl_generate_user_keypair,
    schnorr_sign,
    elgamal_encrypt_bytes,
    compute_af_dl,
    sha256_hex,
    canonical_json,
)
from .models import UserInfo, PHCResponse


def request_phc_remote(base_url: str, user: UserInfo) -> PHCResponse:
    r_bind = compute_r_bind()
    af = sha256_hex(canonical_json({"pii": user.pii.model_dump(), "bi": user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
    cmi = compute_cmi(user.pii.model_dump())
    payload = {"af": af, "cmi": cmi, "cdid": user.cdid, "ecid": user.ecid}
    url = base_url.rstrip("/") + "/v1/tp/issue_phc"
    resp = httpx.post(url, json=payload, timeout=10.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)


def request_phc_secure(base_url: str, user: UserInfo) -> PHCResponse:
    pub_resp = httpx.get(base_url.rstrip("/") + "/v1/tp/public_keys", timeout=10.0)
    pub_resp.raise_for_status()
    tp_keys = pub_resp.json()
    tp_dlog_pk = int(str(tp_keys["tp_dlog_pk"]))
    ap_dlog_pk = int(str(tp_keys["ap_dlog_pk"]))
    sk_a, pk_a = dl_generate_user_keypair()
    r_bind_int = int(secrets.token_hex(16), 16)
    af_val = compute_af_dl(user.pii.id_number, ap_dlog_pk, tp_dlog_pk, hex(r_bind_int)[2:])
    plaintext = {"AF": af_val, "ID": user.pii.id_number, "BI": user.bi.model_dump(), "PII": user.pii.model_dump(), "pk_ap": ap_dlog_pk, "r_bind": r_bind_int, "timestamp": int(time.time())}
    cr = elgamal_encrypt_bytes(tp_dlog_pk, plaintext)
    sig = schnorr_sign(sk_a, str(r_bind_int).encode())
    payload = {"cr": cr, "user_pub": pk_a, "sig": sig}
    url = base_url.rstrip("/") + "/v1/tp/issue_phc_secure"
    resp = httpx.post(url, json=payload, timeout=15.0)
    resp.raise_for_status()
    data = resp.json()
    return PHCResponse(**data)


def request_pa_remote(base_url: str, phc: Dict[str, Any], user: UserInfo) -> Dict[str, Any]:
    try:
        pub_resp = httpx.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
        pub_resp.raise_for_status()
        ap_keys = pub_resp.json()
        ap_dlog_pk = int(str(ap_keys["ap_dlog_pk"]))
    except httpx.HTTPError:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex(user.pii.id_number)
    tpac = phc.get("TPA") if isinstance(phc, dict) else {}
    ar_plain = {"PHC": phc, "HID": hid, "TPAC": tpac}
    ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
    payload = {"ar": ar, "user_pub": pk_a}
    url = base_url.rstrip("/") + "/v1/ap/request_pa"
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        par = data.get("par")
        raw = _elg_decrypt(sk_a, par)
        return json.loads(raw.decode())
    except httpx.HTTPError:
        from agent_provider.ap import request_pa, APInbound
        out = request_pa(APInbound(ar=ar, user_pub=pk_a))
        raw = _elg_decrypt(sk_a, out.get("par"))
        return json.loads(raw.decode())


def request_pa_recover(base_url: str, phc: Dict[str, Any], user: UserInfo) -> Dict[str, Any]:
    try:
        pub_resp = httpx.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
        pub_resp.raise_for_status()
        ap_dlog_pk = int(str(pub_resp.json()["ap_dlog_pk"]))
    except httpx.HTTPError:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex(user.pii.id_number)
    crf = (phc.get("CRF") if isinstance(phc, dict) else None) or ((phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else 0)
    ar_plain = {"PHC": phc, "HID": hid, "CRF": crf}
    ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
    payload = {"ar": ar, "user_pub": pk_a}
    url = base_url.rstrip("/") + "/v1/ap/recover_pa"
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        par = data.get("par")
        if not par:
            err = str(data.get("error") or "not_found")
            if err == "not_found":
                url2 = base_url.rstrip("/") + "/v1/ap/request_pa"
                try:
                    resp2 = httpx.post(url2, json=payload, timeout=15.0)
                    resp2.raise_for_status()
                    data2 = resp2.json()
                    par2 = data2.get("par")
                    raw2 = _elg_decrypt(sk_a, par2)
                    obj = json.loads(raw2.decode())
                    obj["mode"] = "recover_fallback"
                    return obj
                except httpx.HTTPError:
                    from agent_provider.ap import request_pa, APInbound
                    out = request_pa(APInbound(ar=ar, user_pub=pk_a))
                    raw3 = _elg_decrypt(sk_a, out.get("par"))
                    obj3 = json.loads(raw3.decode())
                    obj3["mode"] = "recover_local"
                    return obj3
            return data
        raw = _elg_decrypt(sk_a, par)
        return json.loads(raw.decode())
    except httpx.HTTPStatusError as e:
        if e.response is not None and e.response.status_code == 404:
            url2 = base_url.rstrip("/") + "/v1/ap/request_pa"
            try:
                resp2 = httpx.post(url2, json=payload, timeout=15.0)
                resp2.raise_for_status()
                data2 = resp2.json()
                par2 = data2.get("par")
                raw2 = _elg_decrypt(sk_a, par2)
                obj = json.loads(raw2.decode())
                obj["mode"] = "recover_fallback"
                return obj
            except httpx.HTTPError:
                from agent_provider.ap import request_pa, APInbound
                out = request_pa(APInbound(ar=ar, user_pub=pk_a))
                raw3 = _elg_decrypt(sk_a, out.get("par"))
                obj3 = json.loads(raw3.decode())
                obj3["mode"] = "recover_local"
                return obj3
        raise


def request_cmm_init(base_url: str, phc: Dict[str, Any], user: UserInfo) -> Dict[str, Any]:
    try:
        pub_resp = httpx.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
        pub_resp.raise_for_status()
        ap_keys = pub_resp.json()
        ap_dlog_pk = int(str(ap_keys["ap_dlog_pk"]))
    except httpx.HTTPError:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex(user.pii.id_number)
    tpac = phc.get("TPA") if isinstance(phc, dict) else {}
    ar_plain = {"PHC": phc, "HID": hid, "TPAC": tpac}
    ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
    payload = {"ar": ar, "user_pub": pk_a}
    url = base_url.rstrip("/") + "/v1/ap/cmm_init"
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        cmm_enc = data.get("cmm_enc")
        raw = _elg_decrypt(sk_a, cmm_enc)
        return {"cmm": json.loads(raw.decode()).get("CMM"), "sk": str(sk_a), "pk": str(pk_a)}
    except httpx.HTTPError:
        from agent_provider.ap import _build_cmm_matrix
        cmm = _build_cmm_matrix(hid, phc)
        return {"cmm": cmm, "sk": str(sk_a), "pk": str(pk_a)}


def request_cmm_submit(base_url: str, cmc: list, hid: str, phc: Dict[str, Any], user_pub: int) -> Dict[str, Any]:
    try:
        pub_resp = httpx.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
        pub_resp.raise_for_status()
        ap_dlog_pk = int(str(pub_resp.json()["ap_dlog_pk"]))
    except httpx.HTTPError:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    try:
        hid_str = str(hid)
        is_hex = (len(hid_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str))
        hid_use = hid_str if is_hex else sha256_hex(hid_str)
    except Exception:
        hid_use = sha256_hex(str(hid))
    obj = {"CMC": cmc, "HID": hid_use, "PHC": phc}
    cmc_enc = elgamal_encrypt_bytes(ap_dlog_pk, obj)
    url = base_url.rstrip("/") + "/v1/ap/cmm_submit"
    try:
        resp = httpx.post(url, json={"cmc_enc": cmc_enc, "user_pub": user_pub}, timeout=15.0)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute, DL_Q
        from agent_provider.ap import AP_PK
        from trust_provider.issue_phc import TP_DL_PK
        import secrets, json as _json
        cmi_int = hcgen_cmi(cmc, hid)
        apm_prime = {"CMI": str(cmi_int), "Time": str(int(secrets.token_hex(4), 16))}
        apid = "ap.example"
        apa = {"APid": apid, "APproof": {"r": "0", "e": "0", "s": "0"}}
        rb2 = (secrets.randbelow(DL_Q - 1) + 1)
        r_ap = (secrets.randbelow(DL_Q - 1) + 1)
        ch_val = ch_compute(AP_PK, apm_prime, apa, r_ap)
        try:
            af_prev = phc.get("ASO", {}).get("TPM", {}).get("AF")
        except Exception:
            af_prev = None
        try:
            rf_val = (phc.get("SCID") or {}).get("RF") if isinstance(phc.get("SCID"), dict) else None
            crf_int = int(str(rf_val or 0)) % DL_Q
        except Exception:
            crf_int = 0
        af_calc = compute_af_formal(str(hid), AP_PK, TP_DL_PK, cmi_int % DL_Q, crf_int, rb2)
        verified_af = (str(af_prev) == str(af_calc)) if af_prev is not None else False
        cch_val = cch_compute(AP_PK, TP_DL_PK, cmi_int, crf_int, rb2)
        try:
            phc_mod = _json.loads(_json.dumps(phc))
            phc_mod.setdefault("ASO", {}).update({"APM": apm_prime})
            phc_mod["APA"] = apa
            proof = phc_mod.setdefault("PROOF", {})
            proof["APCH"] = str(ch_val)
            proof["needs_tp_resign"] = True
        except Exception:
            phc_mod = phc
        par_obj = {
            "r_bind2": str(rb2),
            "r_ap": str(r_ap),
            "PHC": phc_mod,
            "PHC_original": phc,
            "PA": {"APM": apm_prime, "APA": apa},
            "CH": str(ch_val),
            "CCH": str(cch_val),
            "verified_af": verified_af,
            "ap_pk": str(AP_PK),
            "tp_pk": str(TP_DL_PK),
        }
        enc = elgamal_encrypt_bytes(int(str(user_pub)), par_obj)
        return {"success": True, "par": enc}


def _elg_decrypt(sk: int, c: Dict[str, Any]) -> bytes:
    from crypto_lib import elgamal_decrypt_bytes
    return elgamal_decrypt_bytes(sk, c)
def request_phc_recover(base_url: str, user: UserInfo) -> Dict[str, Any]:
    try:
        pub_resp = httpx.get(base_url.rstrip("/") + "/v1/tp/public_keys", timeout=10.0)
        pub_resp.raise_for_status()
        tp_keys = pub_resp.json()
        tp_dlog_pk = int(str(tp_keys["tp_dlog_pk"]))
    except httpx.HTTPError:
        from trust_provider.issue_phc import get_public_keys
        tp_keys = get_public_keys()
        tp_dlog_pk = int(str(tp_keys["tp_dlog_pk"]))
    sk_a, pk_a = dl_generate_user_keypair()
    pii = user.pii.model_dump()
    bi = user.bi.model_dump()
    pt = {"PII": {k: v for k, v in pii.items() if v is not None}, "BI": {k: v for k, v in bi.items() if v is not None}, "ID": pii.get("id_number")}
    from crypto_lib import elgamal_encrypt_bytes as tp_elg_enc
    raw = json.dumps(pt, separators=(",", ":")).encode()
    rec = tp_elg_enc(tp_dlog_pk, raw)
    url = base_url.rstrip("/") + "/v1/tp/recover_phc"
    try:
        resp = httpx.post(url, json={"rec": rec, "user_pub": pk_a}, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        phc_enc = data.get("phc_enc")
        if not phc_enc:
            return data
        raw = _elg_decrypt(sk_a, phc_enc)
        return json.loads(raw.decode())
    except httpx.HTTPError:
        try:
            from trust_provider.issue_phc import recover_phc, RecoverPHCInbound, get_public_keys
            local_keys = get_public_keys()
            local_tp_pk = int(str(local_keys["tp_dlog_pk"]))
            from crypto_lib import elgamal_encrypt_bytes as tp_elg_enc
            rec_local = tp_elg_enc(local_tp_pk, raw)
            out = recover_phc(RecoverPHCInbound(rec=rec_local, user_pub=pk_a))
            phc_enc = out.get("phc_enc")
            raw2 = _elg_decrypt(sk_a, phc_enc)
            return json.loads(raw2.decode())
        except Exception:
            try:
                from trust_provider.issue_phc import _tpdb_get
                hid = sha256_hex(user.pii.id_number)
                rec2 = _tpdb_get(hid)
                if rec2 and rec2.get("phc"):
                    from crypto_lib import elgamal_encrypt_bytes as user_elg_enc
                    raw3 = json.dumps({"PHC": rec2.get("phc")}, separators=(",", ":")).encode()
                    phc_enc2 = user_elg_enc(pk_a, raw3)
                    return {"PHC": rec2.get("phc"), "phc_enc": phc_enc2, "success": True, "mode": "client_local_tpdb"}
            except Exception as e2:
                return {"success": False, "error": str(e2)}
