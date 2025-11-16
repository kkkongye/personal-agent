from fastapi import FastAPI, Response
from trust_provider.issue_phc import router as tp_router

app = FastAPI(title="TP Service")
app.include_router(tp_router, prefix="/v1")

@app.get("/tp")
def ui() -> Response:
    html = """
    <!doctype html><html><head><meta charset='utf-8'><title>TP UI</title>
    <style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} pre{background:#f6f8fa;padding:12px;border:1px solid #e1e4e8;overflow:auto}</style>
    </head><body>
    <h2>Trust Provider (TP)</h2>
    <button id=keys>Fetch Public Keys</button>
    <pre id=out></pre>
    <h3>Issue PHC (demo)</h3>
    <button id=issue>POST /v1/tp/issue_phc</button>
    <pre id=phc></pre>
    <script>
    const out = document.getElementById('out');
    const phc = document.getElementById('phc');
    document.getElementById('keys').onclick = async ()=>{
      const r = await fetch('/v1/tp/public_keys'); out.textContent = JSON.stringify(await r.json(), null, 2);
    };
    document.getElementById('issue').onclick = async ()=>{
      const payload = {af:'af.demo', cmi:'cmi.demo', cdid:'cdid:demo', ecid:'g'};
      const r = await fetch('/v1/tp/issue_phc', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)});
      phc.textContent = JSON.stringify(await r.json(), null, 2);
    };
    </script>
    </body></html>
    """
    return Response(content=html, media_type="text/html")