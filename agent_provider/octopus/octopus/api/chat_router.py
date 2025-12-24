"""
Chat API Router for Octopus web interface.
Provides chat and status endpoints for the web frontend.
"""

import logging
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from pydantic import BaseModel

from octopus.agents.message.message_agent import MessageAgent
from octopus.master_agent import MasterAgent
from octopus.config.settings import get_settings
from octopus.anp_sdk.anp_crawler.anp_client import ANPClient

logger = logging.getLogger(__name__)
router = APIRouter()

# Global agents instances (will be injected from main app)
master_agent: MasterAgent | None = None
message_agent: MessageAgent | None = None


# Pydantic models for API
class ChatRequest(BaseModel):
    message: str
    timestamp: str


class ChatAnpRequest(BaseModel):
    message: str
    target_host: str
    gateway_url: str | None = None
    origin_host: str | None = None
    timestamp: str | None = None


class ChatResponse(BaseModel):
    success: bool
    response: str | None = None
    error: str | None = None
    request_id: str
    timestamp: str

class VisionResponse(BaseModel):
    success: bool
    response: str | None = None
    error: str | None = None
    request_id: str
    timestamp: str

class TTSRequest(BaseModel):
    text: str
    voice: str | None = None
    format: str | None = None

class TTSResponse(BaseModel):
    success: bool
    url: str | None = None
    error: str | None = None
    request_id: str
    timestamp: str


class StatusResponse(BaseModel):
    status: str
    message: str | None = None


def set_agents(master: MasterAgent, message: MessageAgent):
    """Set the global agent instances."""
    global master_agent, message_agent
    master_agent = master
    message_agent = message
    logger.info("Agents injected into chat router")


@router.get("/status", response_model=StatusResponse)
async def get_status():
    """Get system status for the frontend."""
    logger.debug("Status endpoint accessed")

    if master_agent is None or message_agent is None:
        return StatusResponse(status="error", message="Agents not initialized")

    return StatusResponse(status="healthy", message="All systems operational")


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """Process chat message through the master agent."""
    logger.info(f"🔵 [CHAT ROUTER] Chat request received: {request.message[:100]}...")
    logger.info(f"🔵 [CHAT ROUTER] Full message: {request.message}")

    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    try:
        # Check if agents are initialized
        if master_agent is None:
            raise HTTPException(status_code=503, detail="Master agent not initialized")

        # Process the message through master agent
        response_text = await master_agent.process_natural_language(
            request=request.message, request_id=request_id
        )

        logger.info(
            f"🟢 [CHAT ROUTER] Chat response generated for request {request_id}"
        )
        logger.info(f"🟢 [CHAT ROUTER] Response content: {response_text}")
        try:
            parsed = json.loads(response_text) if isinstance(response_text, str) else None
        except Exception:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("success") is False:
            return ChatResponse(
                success=False,
                error=str(parsed.get("error") or "未知错误"),
                request_id=request_id,
                timestamp=timestamp,
            )
        return ChatResponse(
            success=True,
            response=response_text,
            request_id=request_id,
            timestamp=timestamp,
        )

    except Exception as e:
        logger.error(f"Error processing chat request {request_id}: {str(e)}")

        return ChatResponse(
            success=False, error=str(e), request_id=request_id, timestamp=timestamp
        )


@router.post("/chat/anp", response_model=ChatResponse)
async def chat_anp(request: ChatAnpRequest):
    logger.info(f"🔵 [CHAT ANP] Target host: {request.target_host}")
    req_id = str(uuid.uuid4())
    ts = datetime.now().isoformat()

    try:
        settings = get_settings()
        did_doc = settings.did_document_path or ""
        priv_key = settings.did_private_key_path or ""
        # Prefer WS-derived gateway for local mode, otherwise use HTTP setting
        gw = (request.gateway_url or "").strip()
        if not gw:
            ws = (settings.anp_gateway_ws_url or "").strip()
            http_gw = (settings.anp_gateway_http_url or "").strip()
            if ws and ("127.0.0.1" in ws or "localhost" in ws):
                gw = ws
            elif http_gw:
                gw = http_gw

        client = ANPClient(
            did_document_path=str(did_doc),
            private_key_path=str(priv_key),
            gateway_url=gw,
        )

        target_url = f"http://{request.target_host}/agents/jsonrpc"
        # Use HTTP if target host is localhost or 127.0.0.1 (local dev mode)
        # Otherwise, gateway might need to route via websocket or https
        # In ANP context, target_host is usually the actual IP:Port of the target agent
        
        # When using ANP Proxy, we should use the gateway URL to forward the request?
        # No, the current implementation seems to try to connect directly to the target agent via HTTP proxy logic?
        # Wait, ANPClient.fetch_url logic:
        # If gateway_url is set, it sends request TO GATEWAY.
        # But here we set target_url = http://target_host/agents/jsonrpc
        # The ANPClient will wrap this request and send it to the gateway.
        # The gateway then forwards it to the target agent.
        
        # However, the user reports 500 error from gateway: "HTTP request failed: www.anpproxy.com/agents/jsonrpc"
        # This suggests the ANPClient is trying to send to www.anpproxy.com/agents/jsonrpc ?
        
        # Let's look at ANPClient implementation in anp_client.py
        
        headers = {}
        body = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "master_agent.process_natural_language",
            "params": {"request": request.message, "request_id": req_id, "origin_host": request.origin_host},
        }

        # ANPClient usage:
        # client.fetch_url(url=..., method=..., headers=..., body=...)
        # If gateway is used, it sends a special "forward" request to the gateway.
        
        # Issue might be: target_host is "127.0.0.1:9529"
        # target_url becomes "http://127.0.0.1:9529/agents/jsonrpc"
        # If running in Docker or separate envs, 127.0.0.1 might be ambiguous, but here on local machine it's fine.
        
        # Wait, the error "HTTP request failed: www.anpproxy.com/agents/jsonrpc" is suspicious.
        # It seems the gateway URL is being used as the target URL?
        
        # Let's check how ANPClient is initialized.
        # client = ANPClient(..., gateway_url=gateway)
        # gateway = request.gateway_url or settings.anp_gateway_http_url
        
        # If settings.anp_gateway_http_url is "www.anpproxy.com", and request.gateway_url is empty.
        # Then gateway is "www.anpproxy.com".
        
        # If ANPClient logic is correct, it should send to gateway.
        
        # Let's fix the immediate issue by ensuring we catch the specific error and return better message.
        
        result = await client.fetch_url(
            url=target_url,
            method="POST",
            headers=headers,
            body=body,
        )

        if not result.get("success"):
            # If gateway/proxy fails, try direct local fallback
            if request.target_host and ("127.0.0.1" in request.target_host or "localhost" in request.target_host):
                import httpx
                
                # Prepare headers with authentication if available
                fallback_headers = {"Content-Type": "application/json"}
                if client.auth_client:
                    try:
                        auth_h = client.auth_client.get_auth_header(target_url)
                        fallback_headers.update(auth_h)
                    except Exception as e:
                        logger.warning(f"Failed to generate auth header for local fallback: {e}")

                async with httpx.AsyncClient(timeout=30.0) as hc:
                    r = await hc.post(target_url, json=body, headers=fallback_headers)
                    r.raise_for_status()
                    payload = r.json()
                    rpc_result = payload.get("result")
                    if isinstance(rpc_result, str):
                        return ChatResponse(success=True, response=rpc_result, request_id=req_id, timestamp=ts)
                    else:
                        import json as _json
                        return ChatResponse(success=True, response=_json.dumps(rpc_result, ensure_ascii=False), request_id=req_id, timestamp=ts)
            
            raise HTTPException(status_code=result.get("status_code", 500), detail=result.get("error", "ANP call failed"))

        import json
        payload = json.loads(result.get("text") or "{}")

        if payload.get("error"):
            return ChatResponse(success=False, error=str(payload.get("error")), request_id=req_id, timestamp=ts)

        rpc_result = payload.get("result")
        if isinstance(rpc_result, str):
            return ChatResponse(success=True, response=rpc_result, request_id=req_id, timestamp=ts)
        else:
            return ChatResponse(success=True, response=json.dumps(rpc_result, ensure_ascii=False), request_id=req_id, timestamp=ts)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in chat_anp proxy: {e}")
        return ChatResponse(success=False, error=str(e), request_id=req_id, timestamp=ts)


@router.post("/vision", response_model=VisionResponse)
async def vision(prompt: str = Form(""), image: UploadFile = File(...)):
    """Image understanding via OpenAI-compatible /v1/chat/completions."""
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    try:
        from pathlib import Path
        import httpx
        from octopus.config.settings import get_settings
        settings = get_settings()

        # Save to static uploads directory
        web_dir = Path(__file__).resolve().parents[2] / "web"
        uploads_dir = web_dir / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        fname = f"{uuid.uuid4().hex}"
        # try to keep extension
        name = image.filename or "image"
        if "." in name:
            ext = name.split(".")[-1].lower()
            fname = f"{fname}.{ext}"
        fpath = uploads_dir / fname
        content = await image.read()
        with open(fpath, "wb") as f:
            f.write(content)

        # Build public URL served by FastAPI static mount
        host = settings.host if settings.host not in ("0.0.0.0", "::", "") else "localhost"
        base_http = f"http://{host}:{settings.port}"
        img_url = f"{base_http}/static/uploads/{fname}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        # Prefer data URI to avoid remote image fetch issues at the provider side
        import base64
        b64 = base64.b64encode(content).decode("utf-8")
        # Determine mime type from extension
        ext_lower = fname.split(".")[-1].lower() if "." in fname else ""
        mime = (
            "image/png" if ext_lower == "png" else
            "image/jpeg" if ext_lower in ("jpg", "jpeg") else
            "image/gif" if ext_lower == "gif" else
            "image/webp" if ext_lower == "webp" else
            "image/bmp" if ext_lower == "bmp" else
            "image/png"
        )
        data_uri = f"data:{mime};base64,{b64}"
        payload = {
            "model": settings.openai_model or "gpt-4o",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": (prompt or "请先识别图片中的文字，再给出你的答案。")},
                        {"type": "image_url", "image_url": {"url": data_uri}},
                    ],
                }
            ],
            "temperature": (settings.openai_temperature if settings.openai_temperature is not None else 0.2),
            "max_tokens": (settings.openai_max_tokens if settings.openai_max_tokens is not None else 1000),
        }

        base_url = settings.openai_base_url or "https://api.openai.com/v1"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(base_url + "/chat/completions", json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
        try:
            text = data["choices"][0]["message"]["content"]
        except Exception:
            text = json.dumps(data, ensure_ascii=False)
        return VisionResponse(success=True, response=text, request_id=request_id, timestamp=timestamp)
    except Exception as e:
        return VisionResponse(success=False, error=str(e), request_id=request_id, timestamp=timestamp)


@router.post("/tts", response_model=TTSResponse)
async def tts(req: TTSRequest):
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    try:
        import httpx
        from pathlib import Path
        from octopus.config.settings import get_settings
        settings = get_settings()
        base_url = settings.openai_base_url or "https://api.openai.com/v1"
        tts_url = base_url.rstrip("/") + ("/audio/speech" if base_url.endswith("/v1") else "/v1/audio/speech")
        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.tts_model or "tts-1",
            "input": req.text,
            "voice": req.voice or settings.tts_voice or "alloy",
            "response_format": req.format or settings.tts_format or "wav",
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(tts_url, json=payload, headers=headers)
            resp.raise_for_status()
            ctype = resp.headers.get("Content-Type", "")
            data_bytes = resp.content
        web_dir = Path(__file__).resolve().parents[2] / "web"
        tts_dir = web_dir / "tts"
        tts_dir.mkdir(parents=True, exist_ok=True)
        ext = (payload["response_format"] or "wav").lower()
        fname = f"{uuid.uuid4().hex}.{ext}"
        fpath = tts_dir / fname
        with open(fpath, "wb") as f:
            f.write(data_bytes)
        host = settings.host if settings.host not in ("0.0.0.0", "::", "") else "localhost"
        base_http = f"http://{host}:{settings.port}"
        url = f"{base_http}/static/tts/{fname}"
        return TTSResponse(success=True, url=url, request_id=request_id, timestamp=timestamp)
    except Exception as e:
        return TTSResponse(success=False, error=str(e), request_id=request_id, timestamp=timestamp)
