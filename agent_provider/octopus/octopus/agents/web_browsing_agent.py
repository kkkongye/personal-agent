from typing import Any
import json

from fastapi import HTTPException

from octopus.agents.base_agent import BaseAgent
from octopus.router.agents_router import agent_interface, register_agent
from octopus.config.settings import get_settings


@register_agent(
    name="web_browsing",
    description="联网搜索智能体",
    version="1.0.0",
    tags=["web", "search", "today", "history"],
)
class WebBrowsingAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="WebBrowsing", description="Web search agent")

    @agent_interface(
        description="执行联网搜索",
        parameters={
            "question": {"description": "要查询的问题，如：今天是几月几号，以及历史的今天发生了什么"}
        },
        returns="string",
        access_level="external",
    )
    async def ask(self, question: str) -> str:
        settings = get_settings()

        base_url = settings.openai_base_url or "https://api.openai.com/v1"
        # 兼容 /v1/responses 路径（用于启用 web_search/input 模式）
        responses_url = (
            base_url.rstrip("/") + "/responses" if base_url.endswith("/v1") else base_url.rstrip("/") + "/v1/responses"
        )

        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }

        # 优先使用 input + web_search（与本地测试脚本一致）
        payload = {
            "model": (getattr(settings, "web_search_model", None) or "gpt-4.1"),
            "input": question,
            "web_search": True,
            "temperature": settings.openai_temperature or 0.2,
            "max_tokens": settings.openai_max_tokens or 1000,
        }

        from datetime import datetime
        def _prefix_date(t: str) -> str:
            ds = datetime.now().strftime("%Y年%m月%d日")
            return f"今天是 {ds}。\n\n{t.strip()}"

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(responses_url, json=payload, headers=headers)
                # 某些提供方不支持 /v1/responses，降级到 /v1/chat/completions（不带 web_search）
                if resp.status_code == 404 or (resp.status_code >= 400 and "responses" in responses_url):
                    chat_url = base_url.rstrip("/") + "/chat/completions"
                    resp = await client.post(chat_url, json={
                        "model": payload["model"],
                        "messages": [{"role": "user", "content": question}],
                        "temperature": payload.get("temperature", 0.2),
                        "max_tokens": payload.get("max_tokens", 1000),
                    }, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"web_browsing_failed: {e}")

        try:
            # 统一提取纯文本，避免返回元数据或完整 JSON
            if isinstance(data, dict):
                # 1) data.text 仅接受字符串（忽略格式元数据）
                if isinstance(data.get("text"), str):
                    return _prefix_date(data["text"])

                # helper: 从 content 列表提取文本
                def _extract_from_content_list(lst):
                    texts = []
                    for c in lst or []:
                        if isinstance(c, dict):
                            t = c.get("text") or c.get("output_text") or c.get("content")
                            if isinstance(t, str):
                                texts.append(t)
                        elif isinstance(c, str):
                            texts.append(c)
                    return texts

                # 2) data.output 可能是字符串或消息列表
                out = data.get("output")
                if isinstance(out, str):
                    return _prefix_date(out)
                if isinstance(out, list):
                    texts = []
                    for item in out:
                        if isinstance(item, dict):
                            texts += _extract_from_content_list(item.get("content"))
                            t = item.get("text") or item.get("output_text")
                            if isinstance(t, str):
                                texts.append(t)
                        elif isinstance(item, str):
                            texts.append(item)
                    if texts:
                        return _prefix_date("\n".join(s.strip() for s in texts if s))

                # 3) data.response.* 结构
                resp_obj = data.get("response")
                if isinstance(resp_obj, dict):
                    rt = resp_obj.get("output_text") or resp_obj.get("text")
                    if isinstance(rt, str):
                        return _prefix_date(rt)
                    r_out = resp_obj.get("output")
                    if isinstance(r_out, list):
                        texts = []
                        for item in r_out:
                            if isinstance(item, dict):
                                texts += _extract_from_content_list(item.get("content"))
                                t = item.get("text") or item.get("output_text")
                                if isinstance(t, str):
                                    texts.append(t)
                        if texts:
                            return _prefix_date("\n".join(s.strip() for s in texts if s))

                # 4) chat completions 回退
                if data.get("choices"):
                    mc = data["choices"][0].get("message", {}).get("content")
                    if isinstance(mc, str):
                        return _prefix_date(mc)

            # 兜底：返回简要错误说明，避免原样 JSON
            return "抱歉，未获取到有效文本结果。请稍后重试或更换问题表达。"
        except Exception:
            return "抱歉，解析联网搜索结果时出现问题。请稍后重试。"
