"""
News Agent - Fetch today's headlines or topic-focused news and summarize with GPT-4.

Features:
- Fetch top headlines or topic-based news via NewsAPI
- Summarize selected articles using OpenAI GPT-4 family models
- Expose simple high-level API: get_news_summary
"""

from __future__ import annotations

import asyncio
import datetime as dt
from typing import Any

import httpx
from openai import AsyncOpenAI

from octopus.agents.base_agent import BaseAgent
from octopus.config.settings import get_settings
from octopus.router.agents_router import agent_interface, register_agent


NEWSAPI_BASE_URL = "https://newsapi.org/v2"


def _iso_date(value: str | None) -> str | None:
    """Validate simple ISO date string (YYYY-MM-DD). Return None if invalid."""
    if not value:
        return None
    try:
        dt.date.fromisoformat(value)
        return value
    except Exception:
        return None


def _trim_article(a: dict[str, Any]) -> dict[str, Any]:
    """Keep a compact subset of NewsAPI article fields."""
    return {
        "title": a.get("title"),
        "description": a.get("description"),
        "url": a.get("url"),
        "source": (a.get("source") or {}).get("name"),
        "author": a.get("author"),
        "publishedAt": a.get("publishedAt"),
    }

def _format_newsapi_error(data: dict[str, Any] | None) -> str:
    if not isinstance(data, dict):
        return "NewsAPI 请求失败"
    code = data.get("code")
    msg = data.get("message") or data.get("error") or ""
    status = data.get("status")
    parts: list[str] = []
    if status and status != "ok":
        parts.append("NewsAPI 错误")
    else:
        parts.append("NewsAPI")
    if code:
        parts.append(str(code))
    if msg:
        parts.append(str(msg))
    result = " ".join([p for p in parts if p]).strip()
    return result or "NewsAPI 请求失败"

def _http_error_message(e: Exception) -> str:
    try:
        resp = getattr(e, "response", None)
        req = getattr(e, "request", None)
        sc = getattr(resp, "status_code", None)
        reason = getattr(resp, "reason_phrase", None)
        url = str(getattr(req, "url", "")) if req else ""
        body = ""
        try:
            body = (resp.text or "")[:200] if resp else ""
        except Exception:
            body = ""
        api_msg = None
        api_code = None
        try:
            jd = resp.json() if resp else None
            if isinstance(jd, dict):
                api_msg = jd.get("message") or jd.get("error")
                api_code = jd.get("code")
        except Exception:
            api_msg = None
        base = f"HTTP {sc} {reason}".strip()
        parts = [p for p in [base, url, api_msg] if p]
        if sc in [401, 403]:
            parts.append("请检查 NewsAPI API Key 是否配置正确")
        if not api_msg and body:
            parts.append(body)
        return " | ".join(parts) or (str(e) or "网络请求失败")
    except Exception:
        return str(e) or "网络请求失败"


@register_agent(
    name="news",
    description="Fetch news via NewsAPI and summarize with GPT-4",
    version="1.0.0",
    tags=["news", "web", "summarization"],
)
class NewsAgent(BaseAgent):
    """Agent for retrieving and summarizing news content."""

    def __init__(self):
        super().__init__(
            name="NewsAgent",
            description="Get headlines or topic news and summarize via GPT-4",
        )

        settings = get_settings()
        # OpenAI client for summarization
        self.openai_client = AsyncOpenAI(
            api_key=settings.openai_api_key, base_url=settings.openai_base_url
        )
        # Prefer a GPT-4 class model if set; fall back to a sensible default
        self.model = settings.openai_model or "gpt-4o-mini"
        self.temperature = (
            0.3 if settings.openai_temperature is None else settings.openai_temperature
        )

        # NewsAPI key from settings or env (.env supported by Settings)
        self.default_newsapi_key = getattr(settings, "newsapi_api_key", None)

    # -----------------------------
    # NewsAPI fetching helpers
    # -----------------------------
    async def _get(self, path: str, params: dict[str, Any], api_key: str) -> dict:
        url = f"{NEWSAPI_BASE_URL}/{path}"
        headers = {"X-Api-Key": api_key}
        timeout = httpx.Timeout(15.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def _resolve_api_key(self, api_key: str | None) -> str:
        key = api_key or self.default_newsapi_key
        if not key:
            raise ValueError(
                "NewsAPI API key not provided. Set Settings.newsapi_api_key or pass api_key."
            )
        return key

    @agent_interface(
        description="Fetch top headlines via NewsAPI",
        parameters={
            "country": {"description": "Country code (e.g., us, cn)"},
            "category": {"description": "Category (business, tech, etc.)"},
            "q": {"description": "Optional search keywords"},
            "language": {"description": "Language code (en, zh, etc.)"},
            "page_size": {"description": "Max articles to return (1-100)"},
            "api_key": {"description": "Override NewsAPI key (optional)"},
        },
        returns="dict",
        access_level="external",
    )
    async def fetch_top_headlines(
        self,
        country: str = "us",
        category: str | None = None,
        q: str | None = None,
        language: str | None = None,
        page_size: int = 10,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        """
        Fetch top headlines from NewsAPI.

        Args:
            country: 2-letter country code (e.g., us, cn)
            category: Optional category filter (business, technology, etc.)
            q: Optional keywords
            language: Language code (en, zh, ...) when country not provided
            page_size: Number of articles (1-100)
            api_key: Optional override NewsAPI key
        """
        key = self._resolve_api_key(api_key)

        params: dict[str, Any] = {
            "pageSize": max(1, min(int(page_size), 100)),
        }
        if country:
            params["country"] = country
        if category:
            params["category"] = category
        if q:
            params["q"] = q
        if language and not country:
            params["language"] = language

        try:
            data = await self._get("top-headlines", params, key)
            status = data.get("status")
            if status != "ok":
                err_msg = _format_newsapi_error(data)
                self.logger.error(f"newsapi top-headlines error: {err_msg}")
                return {"success": False, "error": err_msg}
            articles_raw = data.get("articles", [])
            articles = [
                _trim_article(a)
                for a in articles_raw
                if a and a.get("title") and a.get("url")
            ]
            return {
                "success": True,
                "totalResults": data.get("totalResults", len(articles)),
                "articles": articles,
            }
        except httpx.HTTPError as e:
            err_msg = _http_error_message(e)
            self.logger.error(f"newsapi top-headlines request failed: {err_msg}")
            return {"success": False, "error": err_msg}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @agent_interface(
        description="Search news by topic via NewsAPI",
        parameters={
            "query": {"description": "Search keywords"},
            "from_date": {"description": "Start date YYYY-MM-DD"},
            "to_date": {"description": "End date YYYY-MM-DD"},
            "sort_by": {"description": "publishedAt, popularity, relevancy"},
            "language": {"description": "Language code (en, zh, ...)"},
            "page_size": {"description": "Max articles (1-100)"},
            "api_key": {"description": "Override NewsAPI key (optional)"},
        },
        returns="dict",
        access_level="external",
    )
    async def search_news(
        self,
        query: str,
        from_date: str | None = None,
        to_date: str | None = None,
        sort_by: str = "publishedAt",
        language: str | None = None,
        page_size: int = 10,
        api_key: str | None = None,
    ) -> dict[str, Any]:
        """Search articles using NewsAPI's everything endpoint."""
        key = self._resolve_api_key(api_key)

        params: dict[str, Any] = {
            "q": (query or "").strip(),
            "pageSize": max(1, min(int(page_size), 100)),
            "sortBy": sort_by,
        }
        if language:
            params["language"] = language
        if _iso_date(from_date):
            params["from"] = from_date
        if _iso_date(to_date):
            params["to"] = to_date

        try:
            data = await self._get("everything", params, key)
            status = data.get("status")
            if status != "ok":
                err_msg = _format_newsapi_error(data)
                self.logger.error(f"newsapi everything error: {err_msg}")
                return {"success": False, "error": err_msg}
            articles_raw = data.get("articles", [])
            articles = [
                _trim_article(a)
                for a in articles_raw
                if a and a.get("title") and a.get("url")
            ]
            return {
                "success": True,
                "totalResults": data.get("totalResults", len(articles)),
                "articles": articles,
            }
        except httpx.HTTPError as e:
            err_msg = _http_error_message(e)
            self.logger.error(f"newsapi everything request failed: {err_msg}")
            return {"success": False, "error": err_msg}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # -----------------------------
    # Summarization helpers
    # -----------------------------
    @agent_interface(
        description="Get headlines by topic/category (business, sports, health, science)",
        parameters={
            "topic": {"description": "One of business, sports, health, science (alias supported)"},
            "country": {"description": "Country code for headlines (default us)"},
            "page_size": {"description": "Max articles (1-100)"},
            "api_key": {"description": "Override NewsAPI key (optional)"},
            "return_format": {"description": "Return format: json or text (default json)"},
        },
        returns="dict",
        access_level="external",
    )
    async def get_headlines(
        self,
        topic: str,
        country: str = "us",
        page_size: int = 10,
        api_key: str | None = None,
        return_format: str = "json",
    ) -> dict[str, Any]:
        """
        Convenience wrapper to fetch top headlines by common categories.

        Topic aliases:
          - business: business, 商业, 经济, 财经
          - sports: sports, 体育
          - health: health, 健康, 医疗
          - science: science, 科学
        """
        mapping = {
            "business": {"aliases": ["business", "商业", "经济", "财经"]},
            "sports": {"aliases": ["sports", "体育"]},
            "health": {"aliases": ["health", "健康", "医疗"]},
            "science": {"aliases": ["science", "科学"]},
        }
        normalized = topic.strip().lower()
        category: str | None = None

        for cat, info in mapping.items():
            if normalized in [a.lower() for a in info["aliases"]]:
                category = cat
                break

        if category is None:
            # If not in predefined categories, fallback to keyword search
            data = await self.search_news(
                query=topic, language=None, page_size=page_size, api_key=api_key
            )
        else:
            data = await self.fetch_top_headlines(
                country=country, category=category, page_size=page_size, api_key=api_key
            )

        # Optionally render as Chinese natural language text
        if isinstance(return_format, str) and return_format.lower() == "text":
            if not data.get("success"):
                return f"获取新闻失败：{data.get('error') or '未知错误'}"
            articles = data.get("articles", [])
            if not articles:
                return "未找到相关新闻。"
            # Compose a concise Chinese list
            lines: list[str] = []
            for a in articles:
                title = a.get("title") or ""
                src = a.get("source") or ""
                pub = a.get("publishedAt") or ""
                url = a.get("url") or ""
                lines.append(f"- {title}（{src}，{pub}）{url}")
            header = f"{topic} 相关头条：\n" if topic else "今日头条：\n"
            return header + "\n".join(lines)

        return data

    @agent_interface(
        description="Summarize a list of articles with GPT-4",
        parameters={
            "articles": {"description": "List of articles (title/url/desc)"},
            "language": {"description": "Output language, e.g., zh or en"},
            "style": {"description": "bullet or paragraph"},
            "max_tokens": {"description": "Max output tokens (hint)"},
        },
        returns="dict",
        access_level="external",
    )
    async def summarize_articles(
        self,
        articles: list[dict[str, Any]],
        language: str = "zh",
        style: str = "bullet",
        max_tokens: int = 600,
    ) -> dict[str, Any]:
        """
        Summarize a list of articles into concise takeaways.
        """
        if not articles:
            return {"success": False, "error": "No articles provided"}

        # Prepare compact context
        def to_line(a: dict[str, Any]) -> str:
            published = a.get("publishedAt") or ""
            src = a.get("source") or ""
            title = a.get("title") or ""
            url = a.get("url") or ""
            return f"- {title} — {src} — {published} — {url}"

        lines = [to_line(a) for a in articles]
        context = "\n".join(lines)

        style_hint = (
            "以要点列表形式输出" if style.lower().startswith("bullet") else "以简洁段落形式输出"
        )
        lang_hint = "中文" if language.lower().startswith("zh") else "English"

        prompt = (
            f"请阅读以下新闻条目，提炼今日要闻摘要，突出重点事实、影响与趋势，避免夸张；"
            f"{style_hint}，使用{lang_hint}，并在结尾给出3-5条简短建议或观察。\n\n"
            f"新闻条目：\n{context}\n\n"
            f"要求：\n"
            f"1) 不要虚构内容；2) 尽量合并重复信息；3) 保留关键信息来源或时间；"
            f"4) 如有链接可保留。"
        )

        try:
            resp = await self.openai_client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a precise news summarization assistant."},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.temperature or 0.3,
            )
            content = resp.choices[0].message.content or ""
            return {"success": True, "summary": content}
        except Exception as e:
            return {"success": False, "error": f"OpenAI error: {e}"}

    @agent_interface(
        description="High-level summarization: by topic or with provided articles",
        parameters={
            "topic": {"description": "Topic keywords. If provided, search news and summarize."},
            "articles": {"description": "Optional pre-fetched articles list to summarize"},
            "language": {"description": "Output language, e.g., zh or en"},
            "max_articles": {"description": "Limit number of articles included"},
            "api_key": {"description": "Override NewsAPI key (optional)"},
            "return_format": {"description": "Return format: json or text (default json)"},
        },
        returns="dict",
        access_level="external",
    )
    async def summarize_news(
        self,
        topic: str | None = None,
        articles: list[dict[str, Any]] | None = None,
        language: str = "zh",
        max_articles: int = 8,
        api_key: str | None = None,
        return_format: str = "json",
    ) -> dict[str, Any]:
        """
        Summarize news by topic or summarize provided articles.
        """
        selected_articles: list[dict[str, Any]] = []

        if articles:
            selected_articles = articles[: max(1, int(max_articles))]
        elif topic and topic.strip():
            # Prefer search for arbitrary topics
            news = await self.search_news(
                query=topic.strip(), page_size=max_articles, api_key=api_key
            )
            if not news.get("success"):
                return news
            selected_articles = news.get("articles", [])[: max(1, int(max_articles))]
        else:
            return {"success": False, "error": "Either topic or articles must be provided"}

        summary = await self.summarize_articles(
            articles=selected_articles, language=language, style="bullet"
        )
        # Return natural language text directly if requested
        if isinstance(return_format, str) and return_format.lower() == "text":
            if summary.get("success"):
                header = f"主题：{topic}\n\n" if topic else ""
                return header + (summary.get("summary") or "")
            return f"摘要失败：{summary.get('error') or '未知错误'}"

        return {
            "success": True,
            "topic": topic,
            "articles": selected_articles,
            "summary": summary.get("summary") if summary.get("success") else None,
            "summary_error": None if summary.get("success") else summary.get("error"),
        }

    @agent_interface(
        description="High-level: fetch and summarize news (headlines or by topic)",
        parameters={
            "topic": {"description": "If provided, search by topic instead of headlines"},
            "country": {"description": "Country code for headlines (e.g., us, cn)"},
            "category": {"description": "Headlines category (business, tech, etc.)"},
            "language": {"description": "Output language for summary (zh/en)"},
            "max_articles": {"description": "Max articles to include in summary"},
            "include_links": {"description": "Whether to include links in bullets"},
            "api_key": {"description": "Override NewsAPI key (optional)"},
            "return_format": {"description": "Return format: json or text (default json)"},
        },
        returns="dict",
        access_level="external",
    )
    async def get_news_summary(
        self,
        topic: str | None = None,
        country: str = "us",
        category: str | None = None,
        language: str = "zh",
        max_articles: int = 5,
        include_links: bool = True,  # kept for schema clarity; links already in items
        api_key: str | None = None,
        return_format: str = "json",
    ) -> dict[str, Any]:
        """
        Fetch news (top headlines or by topic) and return a GPT summary plus article list.
        """
        key = self._resolve_api_key(api_key)

        if topic and topic.strip():
            news = await self.search_news(
                query=topic.strip(), page_size=max_articles, api_key=key
            )
        else:
            news = await self.fetch_top_headlines(
                country=country, category=category, page_size=max_articles, api_key=key
            )

        if not news.get("success"):
            return news

        articles = news.get("articles", [])[: max(1, int(max_articles))]
        summary = await self.summarize_articles(
            articles=articles, language=language, style="bullet"
        )
        # Return natural language text directly if requested
        if isinstance(return_format, str) and return_format.lower() == "text":
            if summary.get("success"):
                header = f"主题：{topic}\n\n" if topic else ""
                return header + (summary.get("summary") or "")
            return f"摘要失败：{summary.get('error') or '未知错误'}"

        return {
            "success": True,
            "topic": topic,
            "source": "NewsAPI",
            "totalResults": news.get("totalResults", len(articles)),
            "articles": articles,
            "summary": summary.get("summary") if summary.get("success") else None,
            "summary_error": None if summary.get("success") else summary.get("error"),
        }
