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
    <h3>Identity Reveal</h3>
    <input id="did_input" type="text" placeholder="Enter DID" size="80" />
    <button id="reveal">Reveal Identity</button>
    <pre id="reveal_out"></pre>
    <script>
    const out = document.getElementById('out');
    const reveal_out = document.getElementById('reveal_out');
    document.getElementById('keys').onclick = async ()=>{
      const r = await fetch('/v1/tp/public_keys'); out.textContent = JSON.stringify(await r.json(), null, 2);
    };
    document.getElementById('reveal').onclick = async ()=>{
      const did = document.getElementById('did_input').value;
      if (!did) { reveal_out.textContent = 'Please enter a DID.'; return; }
      const r = await fetch('/v1/tp/reveal', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({did})});
      reveal_out.textContent = JSON.stringify(await r.json(), null, 2);
    };
    </script>
    </body></html>
    """
    return Response(content=html, media_type="text/html")