from fastapi import FastAPI, Response, Body
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Any, Dict
from user.models import UserInfo, PIIModel, BIModel
from user.apply_agent import request_phc_remote, request_pa_remote, request_cmm_init, request_cmm_submit
from user.apply_agent import request_phc_secure
from user.apply_agent import request_pa_recover
from crypto_lib import elgamal_decrypt_bytes
from user.crypto import canonical_json, sha256_hex
from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.issue_phc import TP_DL_PK
from trust_provider.issue_phc import reveal_identity, RevealByDidRequest
from agent_provider.ap import AP_PK
from pic.pic_upload import router as pic_router
import httpx
import os
from user.crypto import compute_r_bind, canonical_json, sha256_hex, compute_cmi, dl_generate_user_keypair
from user.crypto import elgamal_encrypt_bytes
from trust_provider.issue_phc import issue_phc, ASOCompleteModel

app = FastAPI(title="User Service")
app.include_router(pic_router, prefix="/v1")
app.mount("/user/static", StaticFiles(directory=os.path.join(os.getcwd(), "app", "web_user")), name="user_static")

class RequestPHC(BaseModel):
    base_url: str
    user: UserInfo

class RequestPA(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo

class RequestCMMInit(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo

class RequestCMMSubmit(BaseModel):
    base_url: str
    cmc: list
    hid: str
    phc: Dict[str, Any]
    user_sk: str
    user_pk: str

class RequestCreateAgent(BaseModel):
    phc: Dict[str, Any]
    pa: Dict[str, Any]
    cmc: list

class RequestPARecover(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo

class RequestUpdateInit(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo

class RequestUpdateSubmit(BaseModel):
    base_url: str
    cmc: list
    hid: str
    phc: Dict[str, Any]
    user_sk: str
    user_pk: str



class RecoverBothRequest(BaseModel):
    tp_base: str
    ap_base: str
    user: UserInfo
class BenchRequest(BaseModel):
    loops: int = 100
    size: int = 1024
    exp_bits: int = 16
    exp_fixed: int | None = None

@app.post('/user/request_phc')
def user_request_phc(req: RequestPHC) -> Dict[str, Any]:
    from crypto_lib import schnorr_verify
    try:
        res = request_phc_secure(req.base_url, req.user)
        import time
        t0 = time.perf_counter()
        try:
             phc = res.phc
             tpa = phc.get('TPA') or {}
             tpm = (phc.get('ASO') or {}).get('TPM') or {}
             sig = tpa.get('TPproof') or {}
             tpid = tpa.get('TPid')
             _ = bool(schnorr_verify(int(str(tpid)), canonical_json({'TPM': tpm, 'TPid': tpid}).encode(), {'r': int(str(sig.get('r') or 0)), 'e': int(str(sig.get('e') or 0)), 's': int(str(sig.get('s') or 0))}))
        except Exception:
             pass
        t1 = time.perf_counter()
        out = res.model_dump()
        out["perf_user_verify_phc_ms"] = (t1 - t0) * 1000.0
        return out
    except httpx.HTTPError as e:
        from fastapi import HTTPException
        status = getattr(getattr(e, "response", None), "status_code", 502)
        detail = None
        if getattr(e, "response", None) is not None:
            try:
                detail = e.response.json().get("detail")
            except Exception:
                pass
        if status == 403 and str(detail) in {"face_verification_failed", "face_record_not_found"}:
            raise HTTPException(status_code=403, detail=str(detail) or "face_verification_failed")
        if (os.getenv("ALLOW_LEGACY_ISSUE") or "0") == "1":
            r_bind = compute_r_bind()
            af = sha256_hex(canonical_json({"pii": req.user.pii.model_dump(), "bi": req.user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
            cmi = compute_cmi(req.user.pii.model_dump())
            payload = ASOCompleteModel(af=af, cmi=cmi, cdid=req.user.cdid, ecid=req.user.ecid)
            data = issue_phc(payload)
            return data
        raise HTTPException(status_code=status, detail=detail or "phc_secure_failed")

@app.post('/bench/crypto')
def bench_crypto(req: BenchRequest) -> Dict[str, Any]:
    import time, os, secrets
    from crypto_lib import (
        elgamal_encrypt_bytes as elg_enc,
        elgamal_decrypt_bytes as elg_dec,
        schnorr_sign,
        schnorr_verify,
        sym_encrypt,
        sym_decrypt,
        sha256_hex,
        canonical_json,
        inv_mod,
        generate_paillier_keypair,
        paillier_encrypt,
        paillier_decrypt,
        ch_compute,
        cch_compute,
        DL_P,
        dl_generate_keypair,
    )
    from crypto_lib.keys import TP_DL_SK, TP_DL_PK, AP_PK, TP_DL_PK as TP_PK_INT
    loops = int(req.loops)
    msg = os.urandom(int(req.size))
    def avg(fn):
        s = time.perf_counter()
        for _ in range(loops):
            fn()
        e = time.perf_counter()
        return (e - s) * 1000.0 / loops
    te_enc = avg(lambda: elg_enc(int(TP_DL_PK), msg))
    ct_once = elg_enc(int(TP_DL_PK), msg)
    te_dec = avg(lambda: elg_dec(int(TP_DL_SK), ct_once))
    key_sym = os.urandom(32)
    tae = avg(lambda: sym_encrypt(key_sym, msg))
    ct_sym = sym_encrypt(key_sym, msg)
    tad = avg(lambda: sym_decrypt(key_sym, ct_sym))
    th = avg(lambda: sha256_hex(msg.hex()))
    prev0 = sha256_hex("seed")
    data0 = canonical_json({"label": "x", "idx": 0})
    chain_input0 = prev0 + data0
    th_step = avg(lambda: sha256_hex(chain_input0))
    def hash_chain_run():
        prev = sha256_hex("seed")
        for i in range(loops):
            data = canonical_json({"label": "x", "idx": i})
            prev = sha256_hex(prev + data)
        return prev
    s1 = time.perf_counter()
    _ = hash_chain_run()
    thc = (time.perf_counter() - s1) * 1000.0
    thc_avg = thc / max(loops, 1)
    sk_u, pk_u = dl_generate_keypair()
    tsig = avg(lambda: schnorr_sign(int(sk_u), msg))
    sig_once = schnorr_sign(int(sk_u), msg)
    tver = avg(lambda: schnorr_verify(int(pk_u), msg, sig_once))
    apm_obj = {"CMI": "1", "Time": "1"}
    apa_obj = {"APid": str(AP_PK), "APproof": {"r": "0", "e": "0", "s": "0"}}
    r_ap = secrets.randbelow(DL_P - 1) + 1
    tch = avg(lambda: ch_compute(int(AP_PK), apm_obj, apa_obj, int(r_ap)))
    cmi_int = 1
    crf_int = 1
    r_int = secrets.randbelow(DL_P - 1) + 1
    tcch = avg(lambda: cch_compute(int(AP_PK), int(TP_PK_INT), int(cmi_int), int(crf_int), int(r_int)))
    kp = generate_paillier_keypair(256)
    m_int = int.from_bytes(os.urandom(32), "big")
    tpe = avg(lambda: paillier_encrypt(kp.public, m_int))
    c_paillier = paillier_encrypt(kp.public, m_int)
    tpd = avg(lambda: paillier_decrypt(kp.private, c_paillier))
    base = secrets.randbelow(DL_P - 2) + 2
    exp_bits = max(1, int(getattr(req, "exp_bits", 16)))
    exp_rand = secrets.randbelow(1 << exp_bits) + 1
    e_fixed = int(getattr(req, "exp_fixed", 0) or 0) or ((1 << exp_bits) - 1)
    tmu = avg(lambda: pow(base, exp_rand, DL_P))
    tmu_fixed = avg(lambda: pow(base, e_fixed, DL_P))
    texp = avg(lambda: pow(base, exp_rand))
    texp_fixed = avg(lambda: pow(base, e_fixed))
    tinv = avg(lambda: inv_mod(secrets.randbelow(DL_P - 1) + 1, DL_P))
    return {
        "loops": loops,
        "size": int(req.size),
        "results": {
            "Te_enc_ms": te_enc,
            "Te_dec_ms": te_dec,
            "Tae_ms": tae,
            "Tad_ms": tad,
            "Th_ms": th,
            "Th_step_ms": th_step,
            "Thc_ms": thc,
            "Thc_avg_ms": thc_avg,
            "Tsig_ms": tsig,
            "Tver_ms": tver,
            "Tch_ms": tch,
            "Tcch_ms": tcch,
            "Tpe_ms": tpe,
            "Tpd_ms": tpd,
            "Tmu_fixed_ms": tmu_fixed,
            "Texp_fixed_ms": texp_fixed,
            "Tinv_ms": tinv,
            "Tsg_ms": None,
            "TBLS_ms": None,
            "Tsig1_ms": None,
            "Tver1_ms": None,
        },
        "unsupported": ["shamir", "bls", "ecdsa"],
    }

@app.post('/user/recover_phc')
def user_recover_phc(req: RequestPHC) -> Dict[str, Any]:
    from user.apply_agent import request_phc_recover
    from crypto_lib import schnorr_verify, canonical_json
    out = request_phc_recover(req.base_url, req.user)
    phc = out.get('PHC') or out.get('phc') or {}
    tpa = phc.get('TPA') or {}
    tpm = (phc.get('ASO') or {}).get('TPM') or {}
    sig = tpa.get('TPproof') or {}
    tpid = tpa.get('TPid')
    try:
        ok = bool(schnorr_verify(int(str(tpid)), canonical_json({'TPM': tpm, 'TPid': tpid}).encode(), {'r': int(str(sig.get('r') or 0)), 'e': int(str(sig.get('e') or 0)), 's': int(str(sig.get('s') or 0))}))
    except Exception:
        ok = False
    hid = sha256_hex(req.user.pii.id_number)
    return {'success': True, 'phc': phc, 'verified_tp': ok, 'identity': {'hid': hid, 'pii': req.user.pii.model_dump(exclude_none=True), 'bi': req.user.bi.model_dump(exclude_none=True)}}

@app.post('/user/recover_both')
def user_recover_both(req: RecoverBothRequest) -> Dict[str, Any]:
    from user.apply_agent import request_phc_recover
    try:
        hid = sha256_hex(req.user.pii.id_number)
        phc_obj = request_phc_recover(req.tp_base, req.user)
        phc = phc_obj.get('PHC') or phc_obj.get('phc') or {}
        if not phc:
            return {"success": False, "error": "phc_recover_failed", "detail": phc_obj, "identity": {"hid": hid, "pii": req.user.pii.model_dump(exclude_none=True), "bi": req.user.bi.model_dump(exclude_none=True)}}
        pa_obj = request_pa_recover(req.ap_base, phc, req.user)
        did = phc.get("DID") or ((phc.get("ASO") or {}).get("TPM") or {}).get("CDID")
        try:
            sec = reveal_identity(RevealByDidRequest(did=str(did)))
            pii_out = (sec.get("pii") or {})
            bi_out = (sec.get("bi") or {})
        except Exception:
            pii_out = req.user.pii.model_dump(exclude_none=True)
            bi_out = req.user.bi.model_dump(exclude_none=True)
        return {"success": True, "phc": phc, "pa": pa_obj, "identity": {"hid": hid, "pii": pii_out, "bi": bi_out}}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post('/user/request_pa')
def user_request_pa(req: RequestPA) -> Dict[str, Any]:
    try:
        return request_pa_remote(req.base_url, req.phc, req.user)
    except httpx.HTTPError:
        from agent_provider.ap import request_pa, APInbound, AP_PK
        from user.crypto import dl_generate_user_keypair, elgamal_encrypt_bytes
        hid = sha256_hex(req.user.pii.id_number)
        tpac = req.phc.get("TPA") if isinstance(req.phc, dict) else {}
        sk_a, pk_a = dl_generate_user_keypair()
        ar_plain = {"PHC": req.phc, "HID": hid, "TPAC": tpac}
        ar = elgamal_encrypt_bytes(AP_PK, ar_plain)
        out = request_pa(APInbound(ar=ar, user_pub=pk_a))
        from trust_provider.crypto import elgamal_decrypt_bytes
        import json
        raw = elgamal_decrypt_bytes(sk_a, out["par"]).decode()
    return json.loads(raw)

@app.post('/user/cmm_init')
def user_cmm_init(req: RequestCMMInit) -> Dict[str, Any]:
    out = request_cmm_init(req.base_url, req.phc, req.user)
    return out

@app.post('/user/cmm_submit')
def user_cmm_submit(req: RequestCMMSubmit) -> Dict[str, Any]:
    # Use provided user pk/sk; if missing, fall back to a fresh ephemeral pair
    try:
        user_pk_int = int(str(req.user_pk or ""))
        user_sk_int = int(str(req.user_sk or ""))
        if user_pk_int == 0 or user_sk_int == 0:
            raise ValueError("empty keys")
    except Exception:
        user_sk_int, user_pk_int = dl_generate_user_keypair()
    # Build personalized code snapshot to compute CMI from code hash chain
    try:
        import os, shutil, time
        phc = req.phc or {}
        phc_id = (phc.get("id") or "phc").replace(":", "_")
        root = os.path.join(os.getcwd(), "local_store", "agents", phc_id)
        os.makedirs(root, exist_ok=True)
        # normalize HID for binding
        try:
            hid_str0 = str(req.hid or "")
            is_hex0 = (len(hid_str0) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str0))
            hid_use0 = hid_str0 if is_hex0 else sha256_hex(hid_str0)
        except Exception:
            hid_use0 = sha256_hex(str(req.hid))
        # derive allowed agents from CMC features
        features = [m.get("label") for m in (req.cmc[0] if len(req.cmc)>0 else [])]
        mapping = {"text-processing": "text_processor", "news-search": "news", "web-browsing": "web_browsing"}
        allowed_agents = [mapping.get(x, "") for x in features]
        allowed_agents = [x for x in allowed_agents if x]
        personal_dir = os.path.join(root, "octopus_build")
        src_dir = os.path.join(os.getcwd(), "agent_provider", "octopus")
        if os.path.exists(personal_dir):
            shutil.rmtree(personal_dir, ignore_errors=True)
        shutil.copytree(src_dir, personal_dir, dirs_exist_ok=False, ignore=shutil.ignore_patterns(".venv", "venv", "__pycache__", ".git", ".idea", ".vscode"))
        prune_map = {
            "text_processor": os.path.join(personal_dir, "octopus", "agents", "text_processor_agent.py"),
            "news": os.path.join(personal_dir, "octopus", "agents", "news_agent.py"),
            "web_browsing": os.path.join(personal_dir, "octopus", "agents", "web_browsing_agent.py"),
        }
        keep = set(allowed_agents)
        for name, fpath in prune_map.items():
            if name not in keep and os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
        from crypto_lib import dir_code_cmi_hid
        cmi_code_int = dir_code_cmi_hid(personal_dir, hid_use0)
    except Exception:
        cmi_code_int = None
    out = request_cmm_submit(req.base_url, req.cmc, req.hid, req.phc, user_pk_int, cmi_code=cmi_code_int)
    par = out.get("par")
    if not par:
        return out
    raw = elgamal_decrypt_bytes(int(user_sk_int), par).decode()
    import json
    obj = json.loads(raw)
    obj["perf_ap_generate_pa_ms"] = out.get("perf_ap_generate_pa_ms")
    t_verify_start = time.perf_counter()
    # Verify CMI' = HCGen({CMC}, H(ID)) against PA.APM.CMI
    try:
        hid_str = str(req.hid or "")
        is_hex = (len(hid_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str))
        hid_use = hid_str if is_hex else sha256_hex(hid_str)
    except Exception:
        hid_use = sha256_hex(str(req.hid))
    try:
        from crypto_lib import dir_code_cmi_hid
        calc_cmi_int = dir_code_cmi_hid(os.path.join(os.getcwd(), "local_store", "agents", (req.phc.get("id") or "phc").replace(":", "_"), "octopus_build"), hid_use)
    except Exception:
        calc_cmi_int = hcgen_cmi(req.cmc, hid_use)
    pa_cmi = ((obj.get("PA") or {}).get("APM") or {}).get("CMI")
    verified_cmi = (str(calc_cmi_int) == str(pa_cmi))
    # Verify AF formal: AF ?= H(ID) · pk_ap^CMI' · pk_tp^CRF · g^r_bind''
    # Align with AP-provided CMI to avoid any representation mismatch
    try:
        cmi_int = int(str(pa_cmi))
    except Exception:
        cmi_int = int(str(calc_cmi_int))
    # Use SCID.RF as exponent source for formal AF verification
    try:
        rf_val = ((obj.get("PHC") or {}).get("SCID") or {}).get("RF")
        crf_int = int(str(rf_val or 0))
    except Exception:
        crf_int = 0
    try:
        rbind2_int = int(str(obj.get("r_bind2") or 0))
    except Exception:
        rbind2_int = 0
    try:
        ap_pk_int = int(str(obj.get("ap_pk")))
    except Exception:
        ap_pk_int = 0
    try:
        tp_pk_int = int(str(obj.get("tp_pk")))
    except Exception:
        tp_pk_int = 0
    af_calc_user = compute_af_formal(str(hid_use), ap_pk_int, tp_pk_int, cmi_int, crf_int, rbind2_int)
    af_prev = ((obj.get("PHC") or {}).get("ASO") or {}).get("TPM", {}).get("AF")
    verified_af = (str(af_prev) == str(af_calc_user))
    # Verify CH/CCH
    try:
        r_ap_val = int(str(obj.get("r_ap") or 0))
    except Exception:
        r_ap_val = 0
    ch_calc = ch_compute(ap_pk_int, (obj.get("PA") or {}).get("APM") or {}, (obj.get("PA") or {}).get("APA") or {}, r_ap_val)
    cch_calc = cch_compute(ap_pk_int, tp_pk_int, cmi_int, crf_int, rbind2_int)
    try:
        verified_ch = (int(str(ch_calc)) == int(str(obj.get("CH") or 0)))
    except Exception:
        verified_ch = False
    try:
        verified_cch = (int(str(cch_calc)) == int(str(obj.get("CCH") or 0)))
    except Exception:
        verified_cch = False
    # Build PA.MEMORY and encrypt with user's public key (ElGamal)
    from user.crypto import elgamal_encrypt_bytes as user_elg_enc
    memory_payload = {
        "PHC_backup": obj.get("PHC"),
        "CRF": (obj.get("PHC") or {}).get("SCID", {}).get("RF"),
        "CMI": str(calc_cmi_int),
        "r_bind2": obj.get("r_bind2"),
    }
    memory_enc = user_elg_enc(int(str(req.user_pk or "0")), memory_payload)
    obj["verified_cmi"] = verified_cmi
    obj["verified_af_user"] = verified_af
    obj["verified_ch_user"] = verified_ch
    obj["verified_cch_user"] = verified_cch
    obj["memory_enc"] = memory_enc
    try:
        import os, time, json as _json
        store_dir = os.path.join(os.getcwd(), "local_store", "pa_memory")
        os.makedirs(store_dir, exist_ok=True)
        phc_id = ((obj.get("PHC") or {}).get("id") or "phc").replace(":", "_")
        fname = f"{phc_id}_{int(time.time())}.json"
        full_path = os.path.join(store_dir, fname)
        _json.dump({"memory_enc": memory_enc, "meta": {"phc_id": phc_id, "hid": req.hid, "timestamp": int(time.time())}}, open(full_path, "w", encoding="utf-8"), ensure_ascii=False)
        obj["memory_path"] = full_path
    except Exception:
        obj["memory_path"] = None
    try:
        chain = ((obj.get("PHC") or {}).get("ASO") or {}).get("HASH_CHAIN") or {}
        chain_head = chain.get("head")
        local_prev = sha256_hex(str(hid_use))
        idx = 0
        for row in (req.cmc or []):
            for it in (row or []):
                data = canonical_json({"label": str(it.get("label")), "idx": idx})
                local_prev = sha256_hex(local_prev + data)
                idx += 1
        obj["verified_hash_chain_user"] = (str(local_prev) == str(chain_head or ""))
    except Exception:
        obj["verified_hash_chain_user"] = False
    t_verify_end = time.perf_counter()
    obj["perf_user_verify_pa_ms"] = (t_verify_end - t_verify_start) * 1000.0
    return obj

@app.post('/user/create_agent')
def user_create_agent(req: RequestCreateAgent) -> Dict[str, Any]:
    try:
        import os, json, time
        phc = req.phc or {}
        pa = req.pa or {}
        cmc = req.cmc or []
        phc_id = (phc.get("id") or "phc").replace(":", "_")
        did = ((phc.get("ASO") or {}).get("TPM") or {}).get("CDID")
        manifest = {
            "id": phc_id,
            "did": did,
            "modules": {
                "features": [m.get("label") for m in (cmc[0] if len(cmc)>0 else [])],
                "inputs": [m.get("label") for m in (cmc[1] if len(cmc)>1 else [])],
                "reasoning": [m.get("label") for m in (cmc[2] if len(cmc)>2 else [])],
                "knowledge": [m.get("label") for m in (cmc[3] if len(cmc)>3 else [])],
                "outputs": [m.get("label") for m in (cmc[4] if len(cmc)>4 else [])],
            },
            "binding": {
                "PHC_id": phc.get("id"),
                "SCID": phc.get("SCID"),
                "APid": ((pa.get("APA") or {}).get("APid")),
            },
            "proof": {
                "APA": (pa.get("APA") or {}).get("APproof"),
                "APCH": ((phc.get("PROOF") or {}).get("APCH")),
                "APCH_r": ((phc.get("PROOF") or {}).get("APCH_r")),
            },
        }
        root = os.path.join(os.getcwd(), "local_store", "agents", phc_id)
        os.makedirs(root, exist_ok=True)
        # keep a single manifest file; remove old timestamped manifests
        try:
            import glob
            for old in glob.glob(os.path.join(root, "agent_manifest_*.json")):
                try:
                    os.remove(old)
                except Exception:
                    pass
        except Exception:
            pass
        path = os.path.join(root, "agent_manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        features = manifest.get("modules", {}).get("features", [])
        mapping = {"text-processing": "text_processor", "news-search": "news", "web-browsing": "web_browsing"}
        allowed_agents = [mapping.get(x, "") for x in features]
        allowed_agents = [x for x in allowed_agents if x]
        theme = "purple"
        try:
            appearance = [str((m.get("label") if isinstance(m, dict) else m) or "") for m in (cmc[5] if len(cmc)>5 else [])]
            sel = (appearance[0] if appearance else "").lower().strip().replace(" ", "").replace("_", "-")
            if "blue" in sel:
                theme = "blue"
            elif "pink" in sel:
                theme = "pink"
            elif "green" in sel:
                theme = "green"
            elif "purple" in sel:
                theme = "purple"
        except Exception:
            theme = "purple"
        active_path = os.path.join(root, "active_agents.json")
        with open(active_path, "w", encoding="utf-8") as f2:
            json.dump({"allowed_agents": allowed_agents, "theme": theme}, f2, ensure_ascii=False, indent=2)
        bat_path = None
        reason = manifest.get("modules", {}).get("reasoning", [])
        labels = [str(m or "") for m in reason]
        prov = "openai"
        try:
            lab_set = set(labels)
            if ("rag-openai" in lab_set):
                prov = "openai"
            else:
                prov = "openai"
        except Exception:
            prov = "openai"
        inputs = manifest.get("modules", {}).get("inputs", [])
        try:
            allow_img = ("image" in [str(x or "") for x in inputs])
        except Exception:
            allow_img = False
        outputs = manifest.get("modules", {}).get("outputs", [])
        try:
            allow_speech = ("speech" in [str(x or "") for x in outputs])
        except Exception:
            allow_speech = False
        personal_bat = None
        try:
            import shutil
            personal_dir = os.path.join(root, "octopus_build")
            src_dir = os.path.join(os.getcwd(), "agent_provider", "octopus")
            if os.path.exists(personal_dir):
                try:
                    shutil.rmtree(personal_dir, ignore_errors=True)
                except Exception:
                    pass
            shutil.copytree(src_dir, personal_dir, dirs_exist_ok=False)
            prune_map = {
                "text_processor": os.path.join(personal_dir, "octopus", "agents", "text_processor_agent.py"),
                "news": os.path.join(personal_dir, "octopus", "agents", "news_agent.py"),
                "web_browsing": os.path.join(personal_dir, "octopus", "agents", "web_browsing_agent.py"),
            }
            keep = set(allowed_agents)
            for name, fpath in prune_map.items():
                if name not in keep and os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
            personal_bat = os.path.join(root, "launch_octopus_personal.bat")
            with open(personal_bat, "w", encoding="utf-8") as pbf:
                pbf.write("@echo off\n")
                pbf.write("setlocal enabledelayedexpansion\n")
                pbf.write("set SCRIPT_DIR=%~dp0\n")
                pbf.write("set REPO_DIR=%SCRIPT_DIR%..\\..\\..\n")
                pbf.write(f"set PERSONAL_DIR=%REPO_DIR%\\local_store\\agents\\{phc_id}\\octopus_build\n")
                pbf.write(f"set ALLOWED_PATH=%REPO_DIR%\\local_store\\agents\\{phc_id}\\active_agents.json\n")
                pbf.write("pushd \"%REPO_DIR%\"\n")
                pbf.write("set PYEXE=python\n")
                pbf.write("set VENV_PY=%REPO_DIR%\\.venv\\Scripts\\python.exe\n")
                pbf.write("if exist \"%VENV_PY%\" set PYEXE=\"%VENV_PY%\"\n")
                pbf.write("set OCTOPUS_ALLOWED_AGENTS_PATH=%ALLOWED_PATH%\n")
                pbf.write("set MODEL_PROVIDER=openai\n")
                pbf.write("set ANP_SDK_ENABLED=false\n")
                pbf.write("set DOTENV_PATH=%REPO_DIR%\\agent_provider\\octopus\\.env\n")
                pbf.write(f"set INPUTS_INCLUDE_IMAGE={'true' if allow_img else 'false'}\n")
                pbf.write(f"set OUTPUTS_INCLUDE_SPEECH={'true' if allow_speech else 'false'}\n")
                pbf.write(f"set OCTOPUS_THEME={theme}\n")
                pbf.write("echo Checking Octopus dependencies...\n")
                pbf.write("%PYEXE% -m pip install -q openai python-dotenv httpx pydantic pydantic-settings fastapi uvicorn\n")
                pbf.write("set PYTHONPATH=%PERSONAL_DIR%\n")
                pbf.write("cd /d \"%PERSONAL_DIR%\"\n")
                pbf.write("%PYEXE% -m octopus.octopus --port 9527\n")
                pbf.write("if errorlevel 1 (echo Octopus failed to start. Press any key to view logs & pause)\n")
                pbf.write("timeout /t 1 >nul\n")
                pbf.write("start \"\" http://localhost:9527/\n")
                pbf.write("popd\n")
        except Exception:
            personal_bat = None
        return {"success": True, "agent_path": path, "manifest": manifest, "launcher": None, "personal_launcher": personal_bat, "allowed": allowed_agents}
    except Exception:
        return {"success": False}

@app.post('/user/recover_pa')
def user_recover_pa(req: RequestPARecover) -> Dict[str, Any]:
    try:
        return request_pa_recover(req.base_url, req.phc, req.user)
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post('/user/update_init')
def user_update_init(req: RequestUpdateInit) -> Dict[str, Any]:
    try:
        import httpx
        pub_resp = httpx.get(req.base_url.rstrip('/') + '/ap/public_keys', timeout=10.0)
        pub_resp.raise_for_status()
        ap_dlog_pk = int(str(pub_resp.json()["ap_dlog_pk"]))
    except Exception:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    sk_a, pk_a = dl_generate_user_keypair()
    hid = sha256_hex(req.user.pii.id_number)
    crf = (req.phc.get("CRF") if isinstance(req.phc, dict) else None) or ((req.phc.get("SCID") or {}).get("RF") if isinstance(req.phc, dict) else 0)
    ar_plain = {"PHC": req.phc, "HID": hid, "CRF": crf}
    ar = elgamal_encrypt_bytes(ap_dlog_pk, ar_plain)
    try:
        import httpx
        r = httpx.post(req.base_url.rstrip('/') + '/v1/ap/update_init', json={"ar": ar, "user_pub": pk_a}, timeout=15.0)
        r.raise_for_status()
        data = r.json()
        cmm_enc = data.get("cmm_enc")
        raw = elgamal_decrypt_bytes(int(sk_a), cmm_enc)
        import json
        return {"cmm": json.loads(raw.decode()).get("CMM"), "sk": str(sk_a), "pk": str(pk_a)}
    except Exception:
        from agent_provider.ap import _build_cmm_matrix
        cmm = _build_cmm_matrix(hid, req.phc)
        return {"cmm": cmm, "sk": str(sk_a), "pk": str(pk_a), "fallback": True}

@app.post('/user/update_submit')
def user_update_submit(req: RequestUpdateSubmit) -> Dict[str, Any]:
    try:
        import httpx, json
        pub_resp = httpx.get(req.base_url.rstrip('/') + '/v1/ap/public_keys', timeout=10.0)
        pub_resp.raise_for_status()
        ap_dlog_pk = int(str(pub_resp.json()["ap_dlog_pk"]))
    except Exception:
        from agent_provider.ap import AP_PK as ap_dlog_pk
    try:
        user_pk_int = int(str(req.user_pk or ""))
        user_sk_int = int(str(req.user_sk or ""))
        if user_pk_int == 0 or user_sk_int == 0:
            raise ValueError("empty keys")
    except Exception:
        user_sk_int, user_pk_int = dl_generate_user_keypair()
    try:
        hid_str = str(req.hid or "")
        is_hex = (len(hid_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str))
        hid_use = hid_str if is_hex else sha256_hex(hid_str)
    except Exception:
        hid_use = sha256_hex(str(req.hid))
    # Compute code-based CMI for updated configuration
    try:
        import os, shutil
        phc = req.phc or {}
        phc_id = (phc.get("id") or "phc").replace(":", "_")
        root = os.path.join(os.getcwd(), "local_store", "agents", phc_id)
        os.makedirs(root, exist_ok=True)
        features = [m.get("label") for m in (req.cmc[0] if len(req.cmc)>0 else [])]
        mapping = {"text-processing": "text_processor", "news-search": "news", "web_browsing": "web_browsing"}
        allowed_agents = [mapping.get(x, "") for x in features]
        allowed_agents = [x for x in allowed_agents if x]
        personal_dir = os.path.join(root, "octopus_build")
        src_dir = os.path.join(os.getcwd(), "agent_provider", "octopus")
        if os.path.exists(personal_dir):
            shutil.rmtree(personal_dir, ignore_errors=True)
        shutil.copytree(src_dir, personal_dir, dirs_exist_ok=False)
        prune_map = {
            "text_processor": os.path.join(personal_dir, "octopus", "agents", "text_processor_agent.py"),
            "news": os.path.join(personal_dir, "octopus", "agents", "news_agent.py"),
            "web_browsing": os.path.join(personal_dir, "octopus", "agents", "web_browsing_agent.py"),
        }
        keep = set(allowed_agents)
        for name, fpath in prune_map.items():
            if name not in keep and os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception:
                    pass
        from crypto_lib import dir_code_cmi
        cmi_code_int = dir_code_cmi(personal_dir)
    except Exception:
        cmi_code_int = None
    obj = {"CMC": req.cmc, "HID": hid_use, "PHC": req.phc}
    if cmi_code_int is not None:
        obj["CMI_code"] = str(int(cmi_code_int))
    # Send plaintext payload for update_submit; server supports both encrypted and plaintext
    cmc_enc = obj
    url = req.base_url.rstrip('/') + '/v1/ap/update_submit'
    try:
        import httpx
        resp = httpx.post(url, json={"cmc_enc": cmc_enc, "user_pub": user_pk_int}, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        par = data.get("par")
        if not par:
            return data
        raw = elgamal_decrypt_bytes(int(user_sk_int), par).decode()
        obj2 = json.loads(raw)
        try:
            hid_str = str(req.hid or "")
            is_hex = (len(hid_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str))
            hid_use = hid_str if is_hex else sha256_hex(hid_str)
        except Exception:
            hid_use = sha256_hex(str(req.hid))
        calc_cmi_int = hcgen_cmi(req.cmc, hid_use)
        pa_cmi = ((obj2.get("PA") or {}).get("APM") or {}).get("CMI")
        verified_cmi = (str(calc_cmi_int) == str(pa_cmi))
        try:
            ap_pk_int = int(str(obj2.get("ap_pk")))
        except Exception:
            ap_pk_int = 0
        try:
            tp_pk_int = int(str(obj2.get("tp_pk")))
        except Exception:
            tp_pk_int = 0
        try:
            rbind3_int = int(str(obj2.get("r_bind2") or 0))
        except Exception:
            rbind3_int = 0
        try:
            crf_src = ((obj2.get("PHC") or {}).get("SCID") or {}).get("RF")
            crf_int = int(str(crf_src or 0))
        except Exception:
            crf_int = 0
        try:
            cmi_int = int(str(pa_cmi))
        except Exception:
            cmi_int = int(str(calc_cmi_int))
        af_calc_user = compute_af_formal(str(hid_use), ap_pk_int, tp_pk_int, cmi_int, crf_int, rbind3_int)
        af_prev = ((obj2.get("PHC") or {}).get("ASO") or {}).get("TPM", {}).get("AF")
        verified_af = (str(af_prev) == str(af_calc_user))
        obj2["verified_cmi"] = verified_cmi
        obj2["verified_af_user"] = verified_af

        # Update local agent configuration files (manifest, active_agents, launcher)
        try:
            import os, json
            phc_id = (req.phc.get("id") or "phc").replace(":", "_")
            root = os.path.join(os.getcwd(), "local_store", "agents", phc_id)
            os.makedirs(root, exist_ok=True)

            cmc = req.cmc or []
            phc_new = obj2.get("PHC") or req.phc or {}
            pa_new = obj2.get("PA") or {}

            # 1. Update active_agents.json
            features = [m.get("label") for m in (cmc[0] if len(cmc) > 0 else [])]
            mapping = {"text-processing": "text_processor", "news-search": "news", "web-browsing": "web_browsing"}
            allowed_agents = [mapping.get(x, "") for x in features]
            allowed_agents = [x for x in allowed_agents if x]

            theme = "purple"
            try:
                appearance = [str((m.get("label") if isinstance(m, dict) else m) or "") for m in (cmc[5] if len(cmc) > 5 else [])]
                sel = (appearance[0] if appearance else "").lower().strip().replace(" ", "").replace("_", "-")
                if "blue" in sel:
                    theme = "blue"
                elif "pink" in sel:
                    theme = "pink"
                elif "green" in sel:
                    theme = "green"
                elif "purple" in sel:
                    theme = "purple"
            except Exception:
                theme = "purple"

            active_path = os.path.join(root, "active_agents.json")
            with open(active_path, "w", encoding="utf-8") as f2:
                json.dump({"allowed_agents": allowed_agents, "theme": theme}, f2, ensure_ascii=False, indent=2)

            # 2. Update agent_manifest.json
            did = ((phc_new.get("ASO") or {}).get("TPM") or {}).get("CDID")
            manifest = {
                "id": phc_id,
                "did": did,
                "modules": {
                    "features": [m.get("label") for m in (cmc[0] if len(cmc) > 0 else [])],
                    "inputs": [m.get("label") for m in (cmc[1] if len(cmc) > 1 else [])],
                    "reasoning": [m.get("label") for m in (cmc[2] if len(cmc) > 2 else [])],
                    "knowledge": [m.get("label") for m in (cmc[3] if len(cmc) > 3 else [])],
                    "outputs": [m.get("label") for m in (cmc[4] if len(cmc) > 4 else [])],
                },
                "binding": {
                    "PHC_id": phc_new.get("id"),
                    "SCID": phc_new.get("SCID"),
                    "APid": ((pa_new.get("APA") or {}).get("APid")),
                },
                "proof": {
                    "APA": (pa_new.get("APA") or {}).get("APproof"),
                    "APCH": ((phc_new.get("PROOF") or {}).get("APCH")),
                    "APCH_r": ((phc_new.get("PROOF") or {}).get("APCH_r")),
                },
            }
            manifest_path = os.path.join(root, "agent_manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, ensure_ascii=False, indent=2)

            # 3. Update launcher (launch_octopus_personal.bat)
            inputs = manifest.get("modules", {}).get("inputs", [])
            allow_img = ("image" in [str(x or "") for x in inputs])
            outputs = manifest.get("modules", {}).get("outputs", [])
            allow_speech = ("speech" in [str(x or "") for x in outputs])

            personal_bat = os.path.join(root, "launch_octopus_personal.bat")
            with open(personal_bat, "w", encoding="utf-8") as pbf:
                pbf.write("@echo off\n")
                pbf.write("setlocal enabledelayedexpansion\n")
                pbf.write("set SCRIPT_DIR=%~dp0\n")
                pbf.write("set REPO_DIR=%SCRIPT_DIR%..\\..\\..\n")
                pbf.write(f"set PERSONAL_DIR=%REPO_DIR%\\local_store\\agents\\{phc_id}\\octopus_build\n")
                pbf.write(f"set ALLOWED_PATH=%REPO_DIR%\\local_store\\agents\\{phc_id}\\active_agents.json\n")
                pbf.write("pushd \"%REPO_DIR%\"\n")
                pbf.write("set PYEXE=python\n")
                pbf.write("set VENV_PY=%REPO_DIR%\\.venv\\Scripts\\python.exe\n")
                pbf.write("if exist \"%VENV_PY%\" set PYEXE=\"%VENV_PY%\"\n")
                pbf.write("set OCTOPUS_ALLOWED_AGENTS_PATH=%ALLOWED_PATH%\n")
                pbf.write("set MODEL_PROVIDER=openai\n")
                pbf.write("set ANP_SDK_ENABLED=false\n")
                pbf.write("set DOTENV_PATH=%REPO_DIR%\\agent_provider\\octopus\\.env\n")
                pbf.write(f"set INPUTS_INCLUDE_IMAGE={'true' if allow_img else 'false'}\n")
                pbf.write(f"set OUTPUTS_INCLUDE_SPEECH={'true' if allow_speech else 'false'}\n")
                pbf.write(f"set OCTOPUS_THEME={theme}\n")
                pbf.write("echo Checking Octopus dependencies...\n")
                pbf.write("%PYEXE% -m pip install -q openai python-dotenv httpx pydantic pydantic-settings fastapi uvicorn\n")
                pbf.write("set PYTHONPATH=%PERSONAL_DIR%\n")
                pbf.write("cd /d \"%PERSONAL_DIR%\"\n")
                pbf.write("%PYEXE% -m octopus.octopus --port 9527\n")
                pbf.write("if errorlevel 1 (echo Octopus failed to start. Press any key to view logs & pause)\n")
                pbf.write("timeout /t 1 >nul\n")
                pbf.write("start \"\" http://localhost:9527/\n")
                pbf.write("popd\n")

            # Update response with local config
            obj2["manifest"] = manifest
            obj2["allowed_agents"] = allowed_agents
            obj2["theme"] = theme
        except Exception as e:
            print(f"Error updating local agent configuration: {e}")

        return obj2
    except Exception as e:
        return {"success": False, "error": str(e)}



@app.get('/user')
def ui() -> Response:
    import os
    path = os.path.join(os.getcwd(), "app", "web_user", "index.html")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return Response(content=f.read(), media_type='text/html')
    except Exception:
        return Response(content="<h1>Missing user UI</h1>", media_type='text/html')
class RequestPARecover(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo
