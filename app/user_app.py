from fastapi import FastAPI, Response, Body
from pydantic import BaseModel
from typing import Any, Dict
from user.models import UserInfo, PIIModel, BIModel
from user.apply_agent import request_phc_remote, request_pa_remote, request_cmm_init, request_cmm_submit
from trust_provider.crypto import elgamal_decrypt_bytes
from user.crypto import canonical_json, sha256_hex
from trust_provider.crypto import compute_af_formal, hcgen_cmi, ch_compute, cch_compute
from trust_provider.issue_phc import TP_DL_PK
from agent_provider.ap import AP_PK
import httpx
from user.crypto import compute_r_bind, canonical_json, sha256_hex, compute_cmi, dl_generate_user_keypair
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
    user_sk: int | str
    user_pk: int | str

@app.post('/user/request_phc')
def user_request_phc(req: RequestPHC) -> Dict[str, Any]:
    try:
        res = request_phc_remote(req.base_url, req.user)
        return res.model_dump()
    except httpx.HTTPError:
        r_bind = compute_r_bind()
        af = sha256_hex(canonical_json({"pii": req.user.pii.model_dump(), "bi": req.user.bi.model_dump(), "r_bind": r_bind, "pk_ap": "ap.pk.placeholder"}))
        cmi = compute_cmi(req.user.pii.model_dump())
        payload = ASOCompleteModel(af=af, cmi=cmi, cdid=req.user.cdid, ecid=req.user.ecid)
        data = issue_phc(payload)
        return data

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
    calc_cmi_int = hcgen_cmi(req.cmc, req.hid)
    pa_cmi = ((obj.get("PA") or {}).get("APM") or {}).get("CMI")
    verified_cmi = (str(calc_cmi_int) == str(pa_cmi))
    # Verify AF formal: AF ?= H(ID) · pk_ap^CMI' · pk_tp^CRF · g^r_bind''
    cmi_int = int(str(calc_cmi_int))
    try:
        crf_int = int(str(((obj.get("PHC") or {}).get("SCID") or {}).get("RF") or 0))
    except Exception:
        crf_int = 0
    try:
        rbind2_int = int(str(obj.get("r_bind2") or 0))
    except Exception:
        rbind2_int = 0
    af_calc_user = compute_af_formal(str(req.hid), AP_PK, TP_DL_PK, cmi_int, crf_int, rbind2_int)
    af_prev = ((obj.get("PHC") or {}).get("ASO") or {}).get("TPM", {}).get("AF")
    verified_af = (str(af_prev) == str(af_calc_user))
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
    obj["memory_enc"] = memory_enc
    return obj

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
    <button id=issue>Request PHC</button>
    <pre id=phc></pre>
    <button id=fetchcmm disabled>Fetch CMM</button>
    <div id=cmm_ui></div>
    <pre id=cmm_raw></pre>
    <button id=submitcmc disabled>Submit CMC</button>
    <pre id=pa_cmm></pre>
    <button id=reqpa disabled>Request PA</button>
    <pre id=pa_remote></pre>

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
        const paRemote=document.getElementById('pa_remote');
        const cmmUI=document.getElementById('cmm_ui');
        const cmmRaw=document.getElementById('cmm_raw');
        let phcObj=null;
        let cmmObj=null;
        let cmcObj=null;
        
        document.getElementById('issue').onclick = async ()=>{
        const tpBase = tpEl && tpEl.value ? tpEl.value : 'http://127.0.0.1:8001';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const payload={base_url:tpBase,user};
        try{
            const r=await fetch('/user/request_phc',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
            const data=await r.json(); phcObj=data.phc; phcPre.textContent=JSON.stringify(data,null,2); document.getElementById('fetchcmm').disabled=!phcObj; document.getElementById('reqpa').disabled=!phcObj;
        }catch(e){ phcPre.textContent='Request PHC failed: '+(e&&e.message?e.message:'unknown'); }
        };

        document.getElementById('fetchcmm').onclick = async ()=>{
        const apBase = 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const r=await fetch('/user/cmm_init',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:apBase, phc:phcObj, user})});
        const data=await r.json(); cmmObj=data.cmm; cmcObj=(cmmObj||[]).map(row=>row[0]);
        window.__cmmSk = String(data.sk||""); window.__cmmPk = String(data.pk||"");
        cmmRaw.textContent = JSON.stringify({cmm:cmmObj},null,2);
        const htmlRows=(cmmObj||[]).map((row,i)=>{
            const opts=row.map((opt,j)=>`<label><input type=radio name=\"row_${i}\" value='${j}' ${j===0?"checked":""}>${opt.label}</label>`).join(' ');
            return `<div>Row ${i+1}: ${opts}</div>`;
        }).join('');
      cmmUI.innerHTML = htmlRows + `<div><button id='confirmcmc'>Confirm Selection</button></div>`;
      document.getElementById('confirmcmc').onclick = ()=>{
        cmcObj = (cmmObj||[]).map((row,i)=>{ const idx = Number((document.querySelector(`input[name='row_${i}']:checked`)||{value:0}).value); return row[idx]; });
        const keysReady = (window.__cmmSk && window.__cmmPk);
        document.getElementById('submitcmc').disabled = !((cmcObj && cmcObj.length>0) && keysReady);
      };
        };
        
        document.getElementById('submitcmc').onclick = async ()=>{
        const apBase = 'http://127.0.0.1:8002';
        const hid = idnum.value? (await (async()=>{return (idnum.value)})()) : '';
        const r=await fetch('/user/cmm_submit',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({base_url:apBase, cmc:cmcObj||[], hid:hid, phc:phcObj, user_sk: window.__cmmSk||"", user_pk: window.__cmmPk||""})});
        const data=await r.json(); paCmm.textContent=JSON.stringify(data,null,2);
        };
        
        document.getElementById('reqpa').onclick = async ()=>{
        const apBase = apEl && apEl.value ? apEl.value : 'http://127.0.0.1:8002';
        const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
        const payload={base_url:apBase, phc:phcObj, user};
        try{
            const r=await fetch('/user/request_pa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
            const data=await r.json(); paRemote.textContent=JSON.stringify(data,null,2);
        }catch(e){ paRemote.textContent='Request PA failed: '+(e&&e.message?e.message:'unknown'); }
        };
    </script>
    </body></html>
    """
    return Response(content=html, media_type='text/html')