import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/consent", tags=["consent"])


@dataclass
class ConsentItem:
    request_id: str | int
    did: str | None
    method: str
    params_preview: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    future: asyncio.Future | None = None
    origin_host: str | None = None
    request_text: str | None = None
    status: str = "pending"  # pending, accepted, rejected, completed
    result_text: str | None = None


class ConsentManager:
    def __init__(self) -> None:
        self._items: dict[str | int, ConsentItem] = {}

    def list_pending(self) -> list[dict[str, Any]]:
        items = []
        for item in self._items.values():
            if item.future and not item.future.done():
                items.append(
                    {
                        "request_id": item.request_id,
                        "did": item.did,
                        "method": item.method,
                        "params": item.params_preview,
                        "created_at": item.created_at,
                    }
                )
        return items

    def create(self, request_id: str | int, did: str | None, method: str, params_preview: dict[str, Any], origin_host: str | None = None, request_text: str | None = None) -> asyncio.Future:
        if request_id in self._items and self._items[request_id].future and not self._items[request_id].future.done():
            return self._items[request_id].future  # type: ignore[return-value]

        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self._items[request_id] = ConsentItem(
            request_id=request_id,
            did=did,
            method=method,
            params_preview=params_preview,
            future=fut,
            origin_host=origin_host,
            request_text=request_text,
        )
        logger.info(
            "Consent created request_id=%s did=%s method=%s",
            request_id,
            did,
            method,
        )
        return fut

    def decide(self, request_id: str | int, accept: bool) -> None:
        item = self._items.get(request_id)
        if not item or not item.future:
            raise KeyError("Unknown request_id")
        if not item.future.done():
            item.future.set_result(accept)
        item.status = "accepted" if accept else "rejected"
        logger.info(
            "Consent decided request_id=%s accept=%s",
            request_id,
            str(accept),
        )

    def set_result(self, request_id: str | int, result_text: str) -> None:
        item = self._items.get(request_id)
        if not item:
            return
        item.result_text = result_text
        item.status = "completed"
        logger.info("Consent result stored request_id=%s", request_id)


consent_manager = ConsentManager()


@router.get("/pending")
async def list_pending() -> JSONResponse:
    return JSONResponse(content={"pending": consent_manager.list_pending()})


@router.post("/decide")
async def decide(request: Request) -> JSONResponse:
    payload = await request.json()
    request_id = payload.get("request_id")
    decision = payload.get("decision")
    if request_id is None:
        raise HTTPException(status_code=400, detail="Missing request_id")
    if decision not in ["accept", "reject"]:
        raise HTTPException(status_code=400, detail="Invalid decision")
    try:
        consent_manager.decide(request_id, decision == "accept")
    except KeyError:
        raise HTTPException(status_code=404, detail="Unknown request_id")
    item = consent_manager._items.get(request_id)
    return JSONResponse(content={
        "success": True,
        "request_id": request_id,
        "origin_host": item.origin_host if item else None,
        "request_text": item.request_text if item else None,
        "did": item.did if item else None,
    })


@router.get("/status")
async def get_status(request_id: str) -> JSONResponse:
    item = consent_manager._items.get(request_id)  # simple read
    if not item:
        raise HTTPException(status_code=404, detail="Unknown request_id")
    return JSONResponse(content={
        "status": item.status,
        "result": item.result_text,
        "origin_host": item.origin_host,
        "request_text": item.request_text,
    })


def get_consent_manager() -> ConsentManager:
    return consent_manager
