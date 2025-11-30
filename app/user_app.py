from fastapi import FastAPI, Response, Body
from pydantic import BaseModel
from typing import Any, Dict
from user.models import UserInfo, PIIModel, BIModel
from user.apply_agent import request_phc_remote, request_pa_remote, request_cmm_init, request_cmm_submit
from user.apply_agent import request_phc_secure
from user.apply_agent import request_pa_recover
from trust_provider.crypto import elgamal_decrypt_bytes
from user.crypto import canonical_json, sha256_hex
from crypto_lib import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.issue_phc import TP_DL_PK
from agent_provider.ap import AP_PK
import httpx
from user.crypto import compute_r_bind, canonical_json, sha256_hex, compute_cmi, dl_generate_user_keypair
from user.crypto import elgamal_encrypt_bytes
from trust_provider.issue_phc import issue_phc, ASOCompleteModel

app = FastAPI(title="User Service")

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

@app.post('/user/request_phc')
def user_request_phc(req: RequestPHC) -> Dict[str, Any]:
    try:
        res = request_phc_secure(req.base_url, req.user)
        return res.model_dump()
    except httpx.HTTPError:
        r_bind = compute_r_bind()
        af = sha256_hex(canonical_json({"pii": req.user.pii.model_dump(), "bi": req.user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
        cmi = compute_cmi(req.user.pii.model_dump())
        payload = ASOCompleteModel(af=af, cmi=cmi, cdid=req.user.cdid, ecid=req.user.ecid)
        data = issue_phc(payload)
        return data

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
    return {'success': True, 'phc': phc, 'verified_tp': ok, 'identity': {'hid': hid, 'pii': req.user.pii.model_dump(), 'bi': req.user.bi.model_dump()}}

@app.post('/user/recover_both')
def user_recover_both(req: RecoverBothRequest) -> Dict[str, Any]:
    from user.apply_agent import request_phc_recover
    try:
        hid = sha256_hex(req.user.pii.id_number)
        phc_obj = request_phc_recover(req.tp_base, req.user)
        phc = phc_obj.get('PHC') or phc_obj.get('phc') or {}
        if not phc:
            return {"success": False, "error": "phc_recover_failed", "detail": phc_obj, "identity": {"hid": hid, "pii": req.user.pii.model_dump(), "bi": req.user.bi.model_dump()}}
        pa_obj = request_pa_recover(req.ap_base, phc, req.user)
        return {"success": True, "phc": phc, "pa": pa_obj, "identity": {"hid": hid, "pii": req.user.pii.model_dump(), "bi": req.user.bi.model_dump()}}
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
    out = request_cmm_submit(req.base_url, req.cmc, req.hid, req.phc, user_pk_int)
    par = out.get("par")
    if not par:
        return out
    raw = elgamal_decrypt_bytes(int(user_sk_int), par).decode()
    import json
    obj = json.loads(raw)
    # Verify CMI' = HCGen({CMC}, H(ID)) against PA.APM.CMI
    try:
        hid_str = str(req.hid or "")
        is_hex = (len(hid_str) == 64 and all(c in "0123456789abcdefABCDEF" for c in hid_str))
        hid_use = hid_str if is_hex else sha256_hex(hid_str)
    except Exception:
        hid_use = sha256_hex(str(req.hid))
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
        path = os.path.join(root, f"agent_manifest_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        features = manifest.get("modules", {}).get("features", [])
        mapping = {"text-processing": "text_processor", "news-search": "news", "web-browsing": "web_browsing"}
        allowed_agents = [mapping.get(x, "") for x in features]
        allowed_agents = [x for x in allowed_agents if x]
        active_path = os.path.join(root, "active_agents.json")
        with open(active_path, "w", encoding="utf-8") as f2:
            json.dump({"allowed_agents": allowed_agents}, f2, ensure_ascii=False, indent=2)
        bat_path = os.path.join(root, "launch_octopus.bat")
        with open(bat_path, "w", encoding="utf-8") as bf:
            bf.write("@echo off\n")
            bf.write("setlocal enabledelayedexpansion\n")
            bf.write("pushd \"%~dp0\\..\\..\\..\"\n")
            bf.write(f"set OCTOPUS_ALLOWED_AGENTS_PATH=%CD%\\local_store\\agents\\{phc_id}\\active_agents.json\n")
            bf.write("set PYEXE=python\n")
            bf.write("if exist .venv\\Scripts\\python.exe set PYEXE=.venv\\Scripts\\python.exe\n")
            bf.write("cd /d agent_provider\\octopus\n")
            reason = manifest.get("modules", {}).get("reasoning", [])
            labels = [str(m or "") for m in reason]
            prov = "openai"
            try:
                lab_set = set(labels)
                if ("rag-openai" in lab_set) and ("rag-deepseek" in lab_set):
                    prov = "openai"
                elif ("rag-openai" in lab_set):
                    prov = "openai"
                elif ("rag-deepseek" in lab_set):
                    prov = "deepseek"
                else:
                    prov = "openai"
            except Exception:
                prov = "openai"
            bf.write(f"set MODEL_PROVIDER={prov}\n")
            inputs = manifest.get("modules", {}).get("inputs", [])
            try:
                allow_img = ("image" in [str(x or "") for x in inputs])
            except Exception:
                allow_img = False
            bf.write(f"set INPUTS_INCLUDE_IMAGE={'true' if allow_img else 'false'}\n")
            outputs = manifest.get("modules", {}).get("outputs", [])
            try:
                allow_speech = ("speech" in [str(x or "") for x in outputs])
            except Exception:
                allow_speech = False
            bf.write(f"set OUTPUTS_INCLUDE_SPEECH={'true' if allow_speech else 'false'}\n")
            bf.write("start \"OctopusServer\" %PYEXE% -m octopus.octopus --port 9527\n")
            bf.write("timeout /t 2 >nul\n")
            bf.write("start \"\" http://localhost:9527/\n")
            bf.write("popd\n")
        return {"success": True, "agent_path": path, "manifest": manifest, "launcher": bat_path, "allowed": allowed_agents}
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
        pub_resp = httpx.get(req.base_url.rstrip('/') + '/v1/ap/public_keys', timeout=10.0)
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
    obj = {"CMC": req.cmc, "HID": hid_use, "PHC": req.phc}
    cmc_enc = elgamal_encrypt_bytes(ap_dlog_pk, obj)
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
        return obj2
    except Exception as e:
        return {"success": False, "error": str(e)}



@app.get('/user')
def ui() -> Response:
    html = """
    <!doctype html><html><head><meta charset='utf-8'><title>User UI</title>
    <style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} input,button{padding:8px;margin:4px} pre{background:#f6f8fa;padding:12px;border:1px solid #e1e4e8;overflow:auto}</style>
    </head><body>
    <h2>User</h2>
    <div>
        <div><label>TP Base:  http://127.0.0.1:8001</label></div>
        <div><label>AP Base:  http://127.0.0.1:8002</label></div>
    </div>
    <div>
      <label>Name</label><input id=name value="Alice">
      <label>ID</label><input id=idnum value="ID123">
      <label>ID Card</label><input id=idcard value="IDCARD123456">
      <label>Email</label><input id=email value="alice@example.com">
      <label>Passport</label><input id=passport value="P123456789">
    </div>
    <button id=issue>1.请求 PHC</button>
    <pre id=phc></pre>
    <button id=fetchcmm disabled>2.选择PA的配置信息</button>
    <div id=cmm_ui></div>
    <button id=submitcmc disabled>提交PA的配置信息</button>
    <pre id=pa_cmm></pre>
    <pre id=hash_ch></pre>
    <pre id=hash_cch></pre>
    <pre id=hash_status></pre>

    <button id=createAgent disabled>3.创建个人智能体</button>
    <pre id=agent_out></pre>
    <button id=recoverpa disabled>4.PA丢失，恢复PA</button>
    <button id=recoverboth>PHC与PA都丢失，恢复PA</button>
    <pre id=pa_recover></pre>
    <button id=updatepa disabled>5.更新PA的配置信息</button>
    <div id=upd_cmm_ui></div>
    <button id=submitUpdate disabled>提交更新</button>
    <pre id=pa_update></pre>
    
    
    <script>
        const tpEl=document.getElementById('tp');
        const apEl=document.getElementById('ap');
        const name=document.getElementById('name');
        const idnum=document.getElementById('idnum');
        const email=document.getElementById('email');
        const idcard=document.getElementById('idcard');
        const passport=document.getElementById('passport');
        const phcPre=document.getElementById('phc');
    const paCmm=document.getElementById('pa_cmm');
    const hashCH=document.getElementById('hash_ch');
    const hashCCH=document.getElementById('hash_cch');
    const hashStatus=document.getElementById('hash_status');
        const paRecover=document.getElementById('pa_recover');
    const cmmUI=document.getElementById('cmm_ui');
    const zhCat=['功能','输入','推理','知识','输出'];
    const zhLabelMap={
      'text':'文本',
      'voice':'语音',
      'image':'图像',
      'video':'视频',
      'sensor':'传感器',
      'system-event':'系统事件',
      'rule-engine':'规则引擎',
      'bayesian-net':'贝叶斯网络',
      'fuzzy-logic':'模糊逻辑',
      'llm':'大模型',
      'retrieval':'检索',
      'neural-network':'神经网络',
      'planner':'规划',
      'safety-filter':'安全过滤',
      'local-memory':'本地记忆',
      'long-term-memory':'长期记忆',
      'vector-index':'向量索引',
      'knowledge-base':'知识库',
      'shared-org-data':'组织共享数据',
      'browser':'浏览器',
      'external-api':'外部API',
      'database':'数据库',
      'blockchain':'区块链',
      'ipfs':'IPFS',
      'iot-device':'物联网设备',
      'cloud-storage':'云存储',
      'speech':'语音',
      'notification':'通知',
      'json-api':'JSON API',
      'actuation':'执行'
    };
    const zhLabelMapExtra={
      'text-processing':'文本处理',
      'news-search':'新闻查询',
      'payment':'支付',
      'web-browsing':'联网搜索',
      'rag-openai':'RAG+OPENAI',
      'rag-deepseek':'RAG+deepseek',
      'knowledge-pro':'专业知识库',
      'ppt':'ppt'
    };
        let phcObj=null;
        let cmmObj=null;
        let cmcObj=null;
        
        document.getElementById('issue').onclick = async ()=>{
        const tpBase = tpEl && tpEl.value ? tpEl.value : 'http://127.0.0.1:8001';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const payload={base_url:tpBase,user};
        try{
            const r=await fetch('/user/request_phc',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
            const data=await r.json(); phcObj = data.phc || data.PHC || null; phcPre.textContent=JSON.stringify(data,null,2); document.getElementById('fetchcmm').disabled=!phcObj; document.getElementById('recoverpa').disabled=!phcObj; const updBtn=document.getElementById('updatepa'); if(updBtn) updBtn.disabled=!phcObj;
        }catch(e){ phcPre.textContent='Request PHC failed: '+(e&&e.message?e.message:'unknown'); }
        };

        document.getElementById('fetchcmm').onclick = async ()=>{
        const apBase = 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const r=await fetch('/user/cmm_init',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:apBase, phc:phcObj, user})});
      const data=await r.json(); cmmObj=data.cmm; cmcObj=(cmmObj||[]).map(row=>row[0]);
      window.__cmmSk = String(data.sk||""); window.__cmmPk = String(data.pk||"");
        const htmlRows=(cmmObj||[]).map((row,i)=>{
            const opts=row.map((opt,j)=>`<label><input type=checkbox name=\"row_${i}\" value='${j}'>${(zhLabelMap[opt.label]||zhLabelMapExtra[opt.label]||opt.label)}</label>`).join(' ');
            return `<div>${zhCat[i]}：${opts}</div>`;
        }).join('');
      cmmUI.innerHTML = htmlRows;
      document.getElementById('submitcmc').disabled = !(window.__cmmSk && window.__cmmPk);
        };
        
        document.getElementById('submitcmc').onclick = async ()=>{
        const apBase = 'http://127.0.0.1:8002';
        const hid = idnum.value? (await (async()=>{return (idnum.value)})()) : '';
        const cmc = (cmmObj||[]).map((row,i)=>{ const nodes = Array.from(document.querySelectorAll(`input[name='row_${i}']:checked`)); const idxs = nodes.map(n=>Number(n.value)); return row.filter((_,j)=>idxs.includes(j)); });
        cmcObj = cmc;
        const r=await fetch('/user/cmm_submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:apBase, cmc:cmc||[], hid:hid, phc:phcObj, user_sk: window.__cmmSk||"", user_pk: window.__cmmPk||""})});
      const data=await r.json();
      paCmm.textContent=JSON.stringify(data,null,2);
      hashCH.textContent = 'CH: ' + String(data.CH || '');
      hashCCH.textContent = 'CCH: ' + String(data.CCH || '');
      hashStatus.textContent = 'verified_ch: ' + String(data.verified_ch_user || false) + ', verified_cch: ' + String(data.verified_cch_user || false);
      const recoverBtn = document.getElementById('recoverpa'); if(recoverBtn) recoverBtn.disabled = false;
      window.__PHC = data.PHC; window.__PA = data.PA;
      const revealBtn = document.getElementById('reveal'); if(revealBtn) revealBtn.disabled = !(window.__PHC);
      const createBtn = document.getElementById('createAgent');
      if(createBtn){
        createBtn.disabled = !(window.__PHC && window.__PA);
        createBtn.onclick = async ()=>{
          const payload2 = { phc: window.__PHC||{}, pa: window.__PA||{}, cmc: cmcObj||[] };
          const r2=await fetch('/user/create_agent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload2)});
          const data2=await r2.json(); const out = document.getElementById('agent_out'); if(out) out.textContent=JSON.stringify(data2,null,2);
        };
      }
        };
        


        document.getElementById('recoverpa').onclick = async ()=>{
        const apBase = apEl && apEl.value ? apEl.value : 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const payload={base_url:apBase, phc:phcObj, user};
        try{
            const r=await fetch('/user/recover_pa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
            const data=await r.json(); paRecover.textContent=JSON.stringify(data,null,2);
        }catch(e){ paRecover.textContent='Recover PA failed: '+(e&&e.message?e.message:'unknown'); }
        };

        document.getElementById('recoverboth').onclick = async ()=>{
        const tpBase = 'http://127.0.0.1:8001';
        const apBase = 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        try{
            const r=await fetch('/user/recover_both',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({tp_base:tpBase, ap_base:apBase, user})});
            const data=await r.json(); paRecover.textContent=JSON.stringify(data,null,2);
            window.__PHC = data.phc || null;
        }catch(e){ paRecover.textContent='Recover Both failed: '+(e&&e.message?e.message:'unknown'); }
        };

        const revealEl = document.getElementById('reveal');
        if (revealEl) {
          revealEl.onclick = async ()=>{
            const tpBase = 'http://127.0.0.1:8001';
            try{
                const r=await fetch('/user/reveal',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:tpBase, phc:window.__PHC||phcObj||{}})});
                const data=await r.json(); const out=document.getElementById('reveal_out'); if(out) out.textContent=JSON.stringify(data,null,2);
            }catch(e){ const out=document.getElementById('reveal_out'); if(out) out.textContent='Reveal failed: '+(e&&e.message?e.message:'unknown'); }
          };
        }

        document.getElementById('updatepa').onclick = async ()=>{
        const apBase = apEl && apEl.value ? apEl.value : 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const out=document.getElementById('pa_update');
        if(!phcObj){ out.textContent='请先点击 1.Request PHC'; return; }
        try{
          const r=await fetch('/user/update_init',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:apBase, phc:phcObj, user})});
          const data=await r.json(); const cmm=data.cmm; window.__updSk=String(data.sk||""); window.__updPk=String(data.pk||""); window.__lastCMM=cmm;
          const updUI=document.getElementById('upd_cmm_ui');
          const htmlRows=(cmm||[]).map((row,i)=>{ const opts=row.map((opt,j)=>`<label><input type=checkbox name=\"upd_row_${i}\" value='${j}'>${(zhLabelMap[opt.label]||zhLabelMapExtra[opt.label]||opt.label)}</label>`).join(' '); return `<div>${zhCat[i]}：${opts}</div>`; }).join('');
          updUI.innerHTML = htmlRows;
          document.getElementById('submitUpdate').disabled = !((cmm && cmm.length>0) && (window.__updSk && window.__updPk));
        }catch(e){ out.textContent='Update PA failed: '+(e&&e.message?e.message:'unknown'); }
        };

        document.getElementById('submitUpdate').onclick = async ()=>{
        const apBase = apEl && apEl.value ? apEl.value : 'http://127.0.0.1:8002';
        const hid = idnum.value? (await (async()=>{return (idnum.value)})()) : '';
        const cmc = (window.__lastCMM||[]).map((row,i)=>{ const nodes = Array.from(document.querySelectorAll(`input[name='upd_row_${i}']:checked`)); const idxs = nodes.map(n=>Number(n.value)); return row.filter((_,j)=>idxs.includes(j)); });
        const payload={base_url:apBase, cmc:cmc||[], hid:hid, phc:phcObj, user_sk: window.__updSk||"", user_pk: window.__updPk||""};
        const r=await fetch('/user/update_submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const data=await r.json(); const out=document.getElementById('pa_update'); out.textContent=JSON.stringify(data,null,2);
        try{
          const btnId = 'updateCreateAgent';
          let btn = document.getElementById(btnId);
          if(!btn){
            btn = document.createElement('button');
            btn.id = btnId;
            btn.textContent = '更新个人智能体';
            const target = document.getElementById('pa_update');
            target.insertAdjacentElement('afterend', btn);
          }
          let agentOut = document.getElementById('agent_update');
          if(!agentOut){
            agentOut = document.createElement('pre');
            agentOut.id = 'agent_update';
            btn.insertAdjacentElement('afterend', agentOut);
          }
          btn.disabled = !(data && data.PHC && data.PA);
          btn.onclick = async ()=>{
            const payload2 = { phc: data.PHC||{}, pa: data.PA||{}, cmc: cmc||[] };
            const r2 = await fetch('/user/create_agent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload2)});
            const data2 = await r2.json();
            agentOut.textContent = JSON.stringify(data2,null,2);
          };
        }catch(e){}
        };
    </script>
    </body></html>
    """
    return Response(content=html, media_type='text/html')
class RequestPARecover(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo
