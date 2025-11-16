from fastapi import FastAPI, Response, Body
from pydantic import BaseModel
from typing import Any, Dict
from user.models import UserInfo, PIIModel, BIModel
from user.apply_agent import request_phc_remote, request_pa_remote
import httpx
from user.crypto import compute_r_bind, canonical_json, sha256_hex, compute_cmi
from trust_provider.issue_phc import issue_phc, ASOCompleteModel

app = FastAPI(title="User Service")

class RequestPHC(BaseModel):
    base_url: str
    user: UserInfo

class RequestPA(BaseModel):
    base_url: str
    phc: Dict[str, Any]
    user: UserInfo

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

@app.get('/user')
def ui() -> Response:
    html = """
    <!doctype html><html><head><meta charset='utf-8'><title>User UI</title>
    <style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} input,button{padding:8px;margin:4px} pre{background:#f6f8fa;padding:12px;border:1px solid #e1e4e8;overflow:auto}</style>
    </head><body>
    <h2>User</h2>
    <div>
      <label>TP Base:  http://127.0.0.1:8001</label>
      <label>AP Base:  http://127.0.0.1:8002</label>
    </div>
    <div>
      <label>Name</label><input id=name value="Alice">
      <label>ID</label><input id=idnum value="ID123">
      <label>ID Card</label><input id=idcard value="IDCARD123456">
      <label>Email</label><input id=email value="alice@example.com">
      <label>Passport</label><input id=passport value="P123456789">
    </div>
    <button id=issue>Request PHC</button>
    <button id=reqpa disabled>Request PA</button>
    <pre id=phc></pre>
    <pre id=pa></pre>
    <script>
    const tpEl=document.getElementById('tp');
    const apEl=document.getElementById('ap');
    const name=document.getElementById('name');
    const idnum=document.getElementById('idnum');
    const email=document.getElementById('email');
    const idcard=document.getElementById('idcard');
    const passport=document.getElementById('passport');
    const phcPre=document.getElementById('phc');
    const paPre=document.getElementById('pa');
    let phcObj=null;
    document.getElementById('issue').onclick = async ()=>{
      const tpBase = tpEl && tpEl.value ? tpEl.value : 'http://127.0.0.1:8001';
      const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
      const payload={base_url:tpBase,user};
      try{
        const r=await fetch('/user/request_phc',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const data=await r.json(); phcObj=data.phc; phcPre.textContent=JSON.stringify(data,null,2); document.getElementById('reqpa').disabled=!phcObj;
      }catch(e){ phcPre.textContent='Request PHC failed: '+(e&&e.message?e.message:'unknown'); }
    };
    document.getElementById('reqpa').onclick = async ()=>{
      const apBase = apEl && apEl.value ? apEl.value : 'http://127.0.0.1:8002';
      const user={pii:{name:name.value,id_number:idnum.value,id_card_number:(idcard?idcard.value:''),email:email.value},bi:{last_login_ip:'127.0.0.1',passport_number:(passport?passport.value:'')},cdid:'cdid:user.placeholder',ecid:'g'};
      const payload={base_url:apBase, phc:phcObj, user};
      try{
        const r=await fetch('/user/request_pa',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const data=await r.json(); paPre.textContent=JSON.stringify(data,null,2);
      }catch(e){ paPre.textContent='Request PA failed: '+(e&&e.message?e.message:'unknown'); }
    };
    </script>
    </body></html>
    """
    return Response(content=html, media_type='text/html')