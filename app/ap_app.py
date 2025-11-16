from fastapi import FastAPI, Response
from agent_provider.ap import router as ap_router

app = FastAPI(title="AP Service")
app.include_router(ap_router, prefix="/v1")

@app.get("/ap")
def ui() -> Response:
    html = """
    <!doctype html><html><head><meta charset='utf-8'><title>AP UI</title>
    <style>body{font-family:system-ui,Segoe UI,Arial;margin:24px} pre{background:#f6f8fa;padding:12px;border:1px solid #e1e4e8;overflow:auto}</style>
    </head><body>
    <h2>Agent Provider (AP)</h2>
    <button id=keys>Fetch AP Public Keys</button>
    <pre id=out></pre>
    <script>
    const out = document.getElementById('out');
    document.getElementById('keys').onclick = async ()=>{
      const r = await fetch('/v1/ap/public_keys'); out.textContent = JSON.stringify(await r.json(), null, 2);
    };
    </script>
    </body></html>
    """
    return Response(content=html, media_type="text/html")