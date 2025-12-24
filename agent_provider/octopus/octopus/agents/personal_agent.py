"""
Personal Agent - User's personal assistant
"""
import spacy
import requests
import re
from typing import Any
from langdetect import detect

from octopus.agents.base_agent import BaseAgent
from octopus.router.agents_router import agent_interface, register_agent


def detect_language(text: str) -> str:
    """
    Detect the language of the input text.

    Args:
        text: The input text whose language needs to be detected.

    Returns:
        A string representing the detected language ("en" for English, "zh" for Chinese).
    """
    try:
        language = detect(text)
        if language and language.startswith("zh"):
            return "zh-cn"
        return language
    except Exception:
        return "en"


@register_agent(
    name="personal_agent",
    description="User's personal assistant",
    version="1.0.0",
    tags=["assistant", "personal", "multipurpose"],
)
class PersonalAgent(BaseAgent):
    """Multi-purpose intelligent agents designed to meet various user needs"""

    def __init__(self):
        """Initialize the personal agent."""
        super().__init__(
            name="personal_agent",
            description="User's personal assistant",
            tags=["assistant","personal", "multipurpose"],
        )

    def get_info(self) -> dict[str, Any]:
        custom_key = "initialized"
        """Get agent information."""
        return {
            "id": self.info.id,
            "name": self.info.name,
            "description": self.info.description,
            "version": self.info.version,
            "status": self.info.status,
            "tags": self.info.tags,
            "dependencies": self.info.dependencies,
            "created_at": self.info.created_at.isoformat(),
            "state": self.get_state(custom_key),
            "capabilities": self.info.capabilities,
        }

    @agent_interface(
        description="Extract city from text",
        parameters={
            "text": {"description": "Text to extract cities"},
            "language": {"description": "Language of the text"},
        },
        returns="dict",
    )
    def extract_cities_using_spacy(self, text: str) -> list[str]:
        """
        Extract city names from the given text, supports both Chinese and English.

        Args:
            text: The input text to extract city names from.

        Returns:
            A list of extracted city names.
        """

        language = detect_language(text)
        if language == "en":
            nlp = spacy.load("en_core_web_sm")
        elif language == "zh-cn":
            nlp = spacy.load("zh_core_web_sm")
        else:
            nlp = spacy.load("en_core_web_sm")

        doc = nlp(text)

        cities: list[str] = []
        for ent in doc.ents:
            if ent.label_ == "GPE":
                cities.append(ent.text)

        if cities:
            return cities

        raw = (text or "").strip()
        if not raw:
            return []

        zh_match = re.findall(r"[\u4e00-\u9fa5]{2,10}(?:市|区|县)?", raw)
        fallback: list[str] = []
        for m in zh_match:
            name = re.sub(r"[市区县]$", "", m)
            if name:
                fallback.append(name)

        if not fallback and re.fullmatch(r"[\u4e00-\u9fa5]{2,10}(?:市|区|县)?", raw):
            fallback.append(re.sub(r"[市区县]$", "", raw))

        if fallback:
            return fallback

        if language == "en":
            en_raw = re.sub(r"([a-z])([A-Z])", r"\1 \2", raw)
            en_candidates: list[str] = []
            for m in re.finditer(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*(?:city|town)?\b", en_raw):
                name = m.group(1)
                if name:
                    en_candidates.append(name)

            if not en_candidates:
                for m in re.finditer(r"\b([A-Z][a-z]+[A-Z][a-z]+)\b", raw):
                    name = m.group(1)
                    name = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
                    en_candidates.append(name)

            return en_candidates

        return []

    @agent_interface(
        description="Check the data of the cities",
        parameters={
            "cities": {"description": "Cities to check"}
        },
        returns="dict"
    )
    def city_data_check(self, cities: list[str]) -> dict:
        """
        Determine the latitude and longitude of the city.

        Args:
            cities: A list of city names.

        Returns:
            A dictionary containing information about the query city.
        """
        api_key = "6d5c989fbf3c4f539fbe4c54a6480857"
        api_host = "https://pv3qqqpjpm.re.qweatherapi.com"
        if not cities:
            return {"error": "No city found in the text."}

        city_data = []

        for city in cities:
            url = f'{api_host}/geo/v2/city/lookup?location={city}'

            try:
                headers = {
                    "X-QW-Api-Key": api_key
                }
                response = requests.get(url, headers=headers)
                location_data = response.json()

                # 检查请求是否成功
                if location_data.get("code") == "200":
                    location = location_data["location"][0]
                    city_info = {
                        "city": location["name"],
                        "id": location["id"],
                        "latitude": location["lat"],
                        "longitude": location["lon"],
                        "rank": location["rank"],
                        "timezone": location["tz"],
                        "country": location["country"],
                        "link": location["fxLink"]
                    }
                    city_data.append(city_info)
                else:
                    city_data.append({"error": f"Unable to fetch location data for {city}."})
            except Exception as e:
                city_data.append({"error": f"Error fetching data for {city}: {str(e)}"})

        return {"cities": city_data}

    @agent_interface(
        description="Check the weather",
        parameters={
            "text": {"description": "Request for weather information"}
        },
        returns="Any",
        access_level="external"
    )
    def weather_check(self, text: str) -> Any:
        """
        Perform weather query based on city extracted from the text.

        Args:
            text: The text input containing the city name.

        Returns:
            A dictionary containing the weather query results.
        """
        # 提取城市名
        cities = self.extract_cities_using_spacy(text)
        api_key = "6d5c989fbf3c4f539fbe4c54a6480857"
        api_host = "https://pv3qqqpjpm.re.qweatherapi.com"

        if not cities:
            return {"error": "No city found in the text."}

        # 获取所有城市的位置信息
        city_data = self.city_data_check(cities)
        if "error" in city_data:
            return city_data

        summaries: list[str] = []

        # 遍历返回的城市数据，查询天气
        for city_info in city_data["cities"]:
            location_id = city_info["id"]

            # 构建天气查询的 URL
            url = f'{api_host}/v7/weather/now?location={location_id}'

            try:

                headers = {
                    "X-QW-Api-Key": api_key
                }
                response = requests.get(url, headers=headers)
                weather_data = response.json()

                if weather_data.get("code") == "200":
                    now = weather_data.get("now", {})
                    lines: list[str] = []
                    city_name = city_info.get("city", "")
                    lines.append(f"今日{city_name}的天气如下：")
                    if now.get("text"):
                        lines.append(str(now.get("text")))
                    temp = now.get("temp")
                    feels = now.get("feelsLike")
                    if temp or feels:
                        t = f"{temp}c" if temp is not None else ""
                        f = f"体感{feels}c" if feels is not None else ""
                        lines.append("，".join([s for s in [t, f] if s]))
                    wind_dir = now.get("windDir")
                    if isinstance(wind_dir, str) and wind_dir:
                        wd = wind_dir.rstrip("风")
                        lines.append(f"风：{wd}")
                    if now.get("humidity") is not None:
                        lines.append(f"湿度：{now.get('humidity')}%")
                    if now.get("pressure") is not None:
                        lines.append(f"气压：{now.get('pressure')}hPa")
                    if now.get("vis") is not None:
                        lines.append(f"能见度：{now.get('vis')}km")
                    update = weather_data.get("updateTime")
                    if update:
                        lines.append(f"更新时间：{update}")
                    summaries.append("\n".join(lines))
                else:
                    summaries.append(f"{city_info.get('city','')}：查询失败")
            except Exception as e:
                summaries.append(f"{city_info.get('city','')}：查询异常 {str(e)}")

        return "\n\n".join(summaries)
