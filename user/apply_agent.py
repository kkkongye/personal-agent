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
    with httpx.Client(trust_env=False) as client:
        pub_resp = client.get(base_url.rstrip("/") + "/v1/tp/public_keys", timeout=10.0)
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
        resp = client.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        return PHCResponse(**data)


def request_pa_remote(base_url: str, phc: Dict[str, Any], user: UserInfo) -> Dict[str, Any]:
    with httpx.Client(trust_env=False) as client:
        try:
            pub_resp = client.get(base_url.rstrip("/") + "/ap/public_keys", timeout=10.0)
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
            resp = client.post(url, json=payload, timeout=15.0)
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
    with httpx.Client(trust_env=False) as client:
        try:
            pub_resp = client.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
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
            resp = client.post(url, json=payload, timeout=15.0)
            resp.raise_for_status()
            data = resp.json()
            cmm_enc = data.get("cmm_enc")
            raw = _elg_decrypt(sk_a, cmm_enc)
            return {"cmm": json.loads(raw.decode()).get("CMM"), "sk": str(sk_a), "pk": str(pk_a), "perf_ap_verify_phc_ms": data.get("perf_ap_verify_phc_ms")}
        except httpx.HTTPError:
            from agent_provider.ap import _build_cmm_matrix
            cmm = _build_cmm_matrix(hid, phc)
            return {"cmm": cmm, "sk": str(sk_a), "pk": str(pk_a)}


def request_cmm_submit(base_url: str, cmc: list, hid: str, phc: Dict[str, Any], user_pub: int, cmi_code: int | None = None) -> Dict[str, Any]:
    with httpx.Client(trust_env=False) as client:
        try:
            pub_resp = client.get(base_url.rstrip("/") + "/v1/ap/public_keys", timeout=10.0)
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
        if cmi_code is not None:
            try:
                obj["CMI_code"] = str(int(cmi_code))
            except Exception:
                obj["CMI_code"] = str(cmi_code)
        # Use crypto_lib ElGamal with raw JSON bytes for compatibility
        from crypto_lib import elgamal_encrypt_bytes as ap_elg_enc
        raw = json.dumps(obj, separators=(",", ":")).encode()
        cmc_enc = ap_elg_enc(ap_dlog_pk, raw)
        url = base_url.rstrip("/") + "/v1/ap/cmm_submit"
        try:
            resp = client.post(url, json={"cmc_enc": cmc_enc, "user_pub": user_pub}, timeout=15.0)
            resp.raise_for_status()
            data = resp.json()
            return data
        except httpx.HTTPError:
            from agent_provider.ap import cmm_submit, CMMSubmitRequest
            out = cmm_submit(CMMSubmitRequest(cmc_enc=cmc_enc, user_pub=user_pub))
            return out


def _elg_decrypt(sk: int, c: Dict[str, Any]) -> bytes:
    from crypto_lib import elgamal_decrypt_bytes
    return elgamal_decrypt_bytes(sk, c)
def request_phc_recover(base_url: str, user: UserInfo) -> Dict[str, Any]:
    with httpx.Client(trust_env=False) as client:
        try:
            pub_resp = client.get(base_url.rstrip("/") + "/v1/tp/public_keys", timeout=10.0)
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
            resp = client.post(url, json={"rec": rec, "user_pub": pk_a}, timeout=15.0)
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
