import hashlib
import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from octopus.models.phc_models import (
    AnchoringFactor,
    HashChain,
    HashChainEntry,
    PAResponse,
    PHC,
    PersonalAgentConfig,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ap")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_cfg(cfg: PersonalAgentConfig) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for cat in sorted(cfg.selections.keys()):
        for item in sorted(cfg.selections.get(cat, [])):
            pairs.append((cat, item))
    return pairs


def generate_hash_chain(af: AnchoringFactor, cfg: PersonalAgentConfig) -> HashChain:
    base = _sha256_hex((af.user_id + af.af_id).encode("utf-8"))
    prev = base
    entries: list[HashChainEntry] = []
    idx = 0
    for cat, item in _normalize_cfg(cfg):
        payload = json.dumps({"cat": cat, "item": item}, ensure_ascii=False).encode("utf-8")
        h = _sha256_hex(prev.encode("utf-8") + payload)
        entries.append(HashChainEntry(index=idx, item_name=f"{cat}:{item}", item_params={}, prev_hash=prev, hash=h))
        prev = h
        idx += 1
    head = prev
    return HashChain(entries=entries, head=head)


def _verify_af(af: AnchoringFactor) -> None:
    if not af.af_id or not af.user_id:
        raise HTTPException(status_code=400, detail="AF 缺少必要标识")


def _verify_phc_signature(phc: PHC) -> None:
    if phc.signature is None:
        return


def _derive_pa_capabilities(cfg: PersonalAgentConfig) -> list[dict[str, Any]]:
    caps: list[dict[str, Any]] = []
    for cat, item in _normalize_cfg(cfg):
        if cat == "功能" and item == "文本处理":
            caps.append({"agent": "text_processor", "method": "analyze_sentiment"})
            caps.append({"agent": "text_processor", "method": "extract_keywords"})
        if cat == "功能" and item == "新闻查询":
            caps.append({"agent": "news", "method": "get_news_summary"})
        if cat == "输出" and item == "文本":
            caps.append({"agent": "message", "method": "send_text"})
        if cat == "输出" and item == "语音":
            caps.append({"agent": "message", "method": "send_speech"})
        if cat == "输出" and item == "图像":
            caps.append({"agent": "message", "method": "send_image"})
    return caps


@router.post("/personalize")
async def personalize(payload: dict[str, Any]):
    try:
        af = AnchoringFactor(**payload.get("af", {}))
        phc = PHC(**payload.get("phc", {}))
        cfg = PersonalAgentConfig(**payload.get("config", {}))

        _verify_af(af)
        _verify_phc_signature(phc)

        chain = generate_hash_chain(af, cfg)
        af.chain_head = chain.head

        phc.agent_description.setdefault("hash_chain", {})
        phc.agent_description["hash_chain"] = {"head": chain.head, "entries": [e.model_dump() for e in chain.entries]}

        pa_caps = _derive_pa_capabilities(cfg)
        phc.agent_description["pa_config"] = cfg.model_dump()

        manifest = {
            "type": "octopus-pa",
            "endpoints": {"chat": "/v1/chat", "jsonrpc": "/agents/jsonrpc", "ad": "/ad.json"},
            "capabilities": pa_caps,
        }

        resp = PAResponse(updated_phc=phc, pa_manifest=manifest)
        return JSONResponse(content=resp.model_dump(), media_type="application/json; charset=utf-8")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AP 个性化处理错误: {e}")
        raise HTTPException(status_code=500, detail=str(e))