"""
Master Agent - Natural language interface for the Octopus multi-agent system.
"""

import json
import re
import logging
from datetime import datetime
from typing import Any

from openai import AsyncOpenAI, OpenAI

from octopus.agents.base_agent import BaseAgent
from octopus.config.settings import get_settings
from octopus.router.agents_router import agent_interface, register_agent, router

logger = logging.getLogger(__name__)


@register_agent(
    name="master_agent",
    description="Master agent that provides natural language interface and delegates tasks to appropriate sub-agents",
    version="1.0.0",
    tags=["master", "coordinator", "natural_language"],
)
class MasterAgent(BaseAgent):
    """
    Master Agent responsible for:
    1. Providing natural language interface
    2. Agent discovery and selection
    3. Task delegation to appropriate agents
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        **kwargs,
    ):
        """
        Initialize the Master Agent.

        Args:
            api_key: OpenAI API key (optional, will use settings if not provided)
            model: OpenAI model to use (optional, will use settings if not provided)
            base_url: OpenAI base URL (optional, will use settings if not provided)
            **kwargs: Additional configuration
        """
        super().__init__(
            name="MasterAgent", description="Natural language interface", **kwargs
        )

        # Get settings
        settings = get_settings()

        # Validate model provider
        self.model_provider = settings.model_provider.lower()
        if self.model_provider != "openai":
            raise ValueError(
                f"Unsupported model provider: {self.model_provider}. Currently only 'openai' is supported."
            )

        # OpenAI setup using settings
        self.api_key = api_key or settings.openai_api_key
        if not self.api_key:
            raise ValueError(
                "OpenAI API key is required. Set OPENAI_API_KEY in .env file or pass api_key parameter."
            )

        self.model = model or settings.openai_model
        self.base_url = base_url or settings.openai_base_url
        self.temperature = settings.openai_temperature
        self.max_tokens = settings.openai_max_tokens

        # Create client based on provider
        self._initialize_client()

        # Use the configured model directly
        self.effective_model = self.model

        self.logger.info(
            f"MasterAgent initialized with provider: {self.model_provider}, model: {self.effective_model}"
        )
        if self.base_url:
            self.logger.info(
                f"Using {self.model_provider.upper()} base URL: {self.base_url}"
            )

        self.logger.info(
            f"{self.model_provider.upper()} settings - Temperature: {self.temperature}, Max tokens: {self.max_tokens}"
        )

    def _initialize_client(self):
        """Initialize the appropriate client based on model provider."""
        if self.model_provider == "openai":
            # Create OpenAI client with proper Azure OpenAI configuration
            client_kwargs = {"api_key": self.api_key}

            # Use base_url directly without complex Azure URL construction
            if self.base_url:
                client_kwargs["base_url"] = self.base_url

            self.client = OpenAI(**client_kwargs)
            self.async_client = AsyncOpenAI(**client_kwargs)
        else:
            raise ValueError(f"Unsupported model provider: {self.model_provider}")

    def initialize(self):
        """Custom initialization."""
        # Discover available agents
        self._discover_agents()

    def cleanup(self):
        """Cleanup resources."""
        pass

    def _discover_agents(self):
        """Discover and catalog available agents."""
        agents = router.list_agents()
        self.logger.info(f"Discovered {len(agents)} agents:")
        for agent in agents:
            self.logger.info(f"  - {agent['name']}: {agent['description']}")

    def _get_agent_capabilities(self) -> list[dict[str, Any]]:
        """Get detailed capabilities of all available agents."""
        agents = router.list_agents()
        capabilities = []

        for agent in agents:
            # Skip self
            if agent["name"] == "master_agent":
                continue

            # Get agent registration to access methods
            agent_registration = router.get_agent(agent["name"])
            if agent_registration and agent_registration.methods:
                # Convert MethodInfo objects to dict for serialization
                methods_dict = {}
                for method_name, method_info in agent_registration.methods.items():
                    methods_dict[method_name] = {
                        "description": method_info.description,
                        "parameters": method_info.parameters,
                        "returns": method_info.returns,
                    }

                capabilities.append({
                    "name": agent["name"],
                    "description": agent["description"],
                    "methods": methods_dict,
                })

        return capabilities

    @agent_interface(
        description="Process natural language request and delegate to appropriate agent",
        parameters={
            "request": {
                "type": "string",
                "description": "Natural language request or task",
            },
            "request_id": {
                "type": "string",
                "description": "Unique identifier for this request",
            },
        },
        returns="string",
        access_level="external",
    )
    async def process_natural_language(self, request: str, request_id: str) -> str:
        """
        Process natural language request and delegate to appropriate agent.

        Args:
            request: Natural language request or task
            request_id: Unique identifier for this request

        Returns:
            String response from the delegated agent
        """
        self.logger.info(
            f"🔵 [MASTER AGENT] Processing natural language request [{request_id}]: {request}"
        )

        try:
            # Get available agents and their capabilities
            available_agents = self._get_agent_capabilities()
            self.logger.info(
                f"🔵 [MASTER AGENT] Found {len(available_agents)} available agents"
            )

            # If no agents available, provide fallback response
            if not available_agents:
                return "Sorry, there are currently no available agents to handle your request. Please try again later."

            # 1) Fast path: direct parse like "使用 agent.method ..."
            direct = self._try_direct_agent_selection(request, available_agents)
            if direct:
                self.logger.info(
                    f"🔵 [MASTER AGENT] Direct selection from user instruction: {direct}"
                )
                result = await self._execute_agent_method(direct)
                self.logger.info("🟢 [MASTER AGENT] Agent execution completed successfully")
                try:
                    return self._format_result_natural_language(result, request)
                except Exception:
                    return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, (dict, list)) else str(result)

            # 2) Use LLM to analyze and select agent
            agent_selection = self._select_agent_for_request(request, available_agents)

            # Validate agent selection
            if not agent_selection or not agent_selection.get("agent_name"):
                # 3) Heuristic fallback on timeout/uncertain selection
                heuristic = self._heuristic_agent_selection(request, available_agents)
                if heuristic:
                    self.logger.info(
                        f"🟡 [MASTER AGENT] Falling back to heuristic selection: {heuristic}"
                    )
                    result = await self._execute_agent_method(heuristic)
                    self.logger.info("🟢 [MASTER AGENT] Agent execution completed successfully")
                    try:
                        return self._format_result_natural_language(result, request)
                    except Exception:
                        return json.dumps(result, ensure_ascii=False, indent=2) if isinstance(result, (dict, list)) else str(result)

                # Provide a helpful response with available capabilities
                agent_list = [
                    f"- {agent['name']}: {agent['description']}" for agent in available_agents
                ]
                return (
                    "Sorry, I cannot determine which agent to use to handle your request.\n\n"
                    + "Currently available agents:\n"
                    + chr(10).join(agent_list)
                    + "\n\nYou can try to rephrase your request, or directly specify the function you want to use."
                )

            # Execute the selected agent method
            self.logger.info(
                f"🔵 [MASTER AGENT] Executing agent method: {agent_selection}"
            )
            result = await self._execute_agent_method(agent_selection)

            # Return the result as a string
            self.logger.info("🟢 [MASTER AGENT] Agent execution completed successfully")
            if isinstance(result, dict):
                return json.dumps(result, ensure_ascii=False, indent=2)
            else:
                return str(result)

        except Exception as e:
            self.logger.error(
                f"Error processing natural language request [{request_id}]: {str(e)}"
            )
            return f"Sorry, an error occurred while processing your request: {str(e)}"

    def _select_agent_for_request(
        self, request: str, available_agents: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Use OpenAI to select the most appropriate agent for the request."""
        system_prompt = """You are an intelligent agent selector for a multi-agent system.
Given a natural language request, analyze it and select the most appropriate agent and method to handle it.

Available agents and their capabilities:
{agents_info}

Respond in JSON format with the following structure:
{{
    "agent_name": "selected_agent_name",
    "method_name": "selected_method_name",
    "parameters": {{}},
    "confidence": 0.95,
    "reasoning": "explanation of why this agent was selected"
}}

If no suitable agent is found, respond with:
{{
    "agent_name": null,
    "method_name": null,
    "parameters": null,
    "confidence": 0.0,
    "reasoning": "no suitable agent found"
}}"""

        user_prompt = f"Request: {request}"

        try:
            # Use a conservative token/temperature and short timeout for snappy selection
            selection_max_tokens = min(self.max_tokens or 256, 256)
            response = self.client.chat.completions.create(
                model=self.effective_model,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt.format(
                            agents_info=json.dumps(
                                available_agents, indent=2, ensure_ascii=False
                            )
                        ),
                    },
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.0,
                max_tokens=selection_max_tokens,
                timeout=10,  # seconds
            )

            response_text = response.choices[0].message.content
            self.logger.debug(f"OpenAI response text: {response_text}")

            # Try to parse the JSON response
            try:
                # Clean the response text (remove extra whitespace)
                clean_response = response_text.strip()
                self.logger.debug(f"Clean response text: {clean_response}")

                selection_result = json.loads(clean_response)
                self.logger.debug(f"Parsed JSON: {selection_result}")

                # Validate the response structure
                if not isinstance(selection_result, dict):
                    self.logger.error(
                        f"Response is not a dict: {type(selection_result)}"
                    )
                    return None

                if "agent_name" not in selection_result:
                    self.logger.error(
                        f"Missing 'agent_name' in response: {selection_result}"
                    )
                    return None

                return selection_result

            except json.JSONDecodeError as e:
                self.logger.error(f"JSON decode error: {e}")
                self.logger.error(f"Raw response: {repr(response_text)}")
                # Try to find the JSON part if there's extra text
                try:
                    # Look for JSON-like structure in the response
                    start_idx = response_text.find("{")
                    end_idx = response_text.rfind("}") + 1
                    if start_idx != -1 and end_idx != -1:
                        json_part = response_text[start_idx:end_idx]
                        self.logger.debug(f"Extracted JSON part: {json_part}")
                        selection_result = json.loads(json_part)
                        return selection_result
                except:
                    pass
                return None

        except Exception as e:
            self.logger.error(f"Error in agent selection: {e}")
            return None

    def _extract_trailing_text(self, request: str) -> str | None:
        """Extract the likely target text from a multi-line or colon-delimited request."""
        if not request:
            return None
        # Prefer last non-empty line as payload
        lines = [ln.strip() for ln in request.splitlines() if ln.strip()]
        if len(lines) >= 2:
            return lines[-1]
        # Try colon-delimited content after full-width or half-width colon
        if "：" in request:
            return request.split("：", 1)[1].strip() or None
        if ":" in request:
            return request.split(":", 1)[1].strip() or None
        return None

    def _try_direct_agent_selection(
        self, request: str, available_agents: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Parse direct instruction like '使用 agent.method ...' or 'use agent.method ...'."""
        try:
            m = re.search(r"(?:使用|use)\s+([a-zA-Z_][\w]*)\.([a-zA-Z_][\w]*)", request)
            if not m:
                # Also allow bare agent.method
                m = re.search(r"\b([a-zA-Z_][\w]*)\.([a-zA-Z_][\w]*)\b", request)
            if not m:
                return None

            agent_name, method_name = m.group(1), m.group(2)
            # Validate against available agents
            names = {a["name"] for a in available_agents}
            if agent_name not in names:
                return None

            # Build parameters heuristically for common methods
            params: dict[str, Any] = {}
            if agent_name == "text_processor" and method_name == "analyze_sentiment":
                text = self._extract_trailing_text(request) or request
                params = {"text": text}

            return {
                "agent_name": agent_name,
                "method_name": method_name,
                "parameters": params,
                "confidence": 1.0,
                "reasoning": "Direct user instruction",
            }
        except Exception:
            return None

    def _heuristic_agent_selection(
        self, request: str, available_agents: list[dict[str, Any]]
    ) -> dict[str, Any] | None:
        """Heuristic mapping when LLM selection fails (e.g., timeout).

        Very conservative rules targeting built-in text_processor methods.
        """
        lower = request.lower()
        has_text_processor = any(a["name"] == "text_processor" for a in available_agents)
        if not has_text_processor:
            return None

        # Sentiment
        if ("情感" in request) or ("sentiment" in lower):
            text = self._extract_trailing_text(request) or request
            return {
                "agent_name": "text_processor",
                "method_name": "analyze_sentiment",
                "parameters": {"text": text},
                "confidence": 0.7,
                "reasoning": "Heuristic: sentiment keywords detected",
            }

        # Keywords
        if ("关键词" in request) or ("keyword" in lower):
            text = self._extract_trailing_text(request) or request
            return {
                "agent_name": "text_processor",
                "method_name": "extract_keywords",
                "parameters": {"text": text, "top_n": 10},
                "confidence": 0.6,
                "reasoning": "Heuristic: keyword extraction detected",
            }

        # Summary
        if ("摘要" in request) or ("summary" in lower) or ("summarize" in lower):
            text = self._extract_trailing_text(request) or request
            return {
                "agent_name": "text_processor",
                "method_name": "summarize_text",
                "parameters": {"text": text, "num_sentences": 3},
                "confidence": 0.6,
                "reasoning": "Heuristic: summary detected",
            }

        return None

    async def _execute_agent_method(self, agent_selection: dict[str, Any]) -> Any:
        """Execute the selected agent method."""
        agent_name = agent_selection["agent_name"]
        method_name = agent_selection["method_name"]
        parameters = agent_selection.get("parameters", {})

        self.logger.info(
            f"Executing {agent_name}.{method_name} with parameters: {parameters}"
        )

        try:
            # Call the agent method through the router asynchronously
            result = await router.execute_agent_method_async(
                agent_name, method_name, parameters
            )

            self.logger.info("Agent execution completed successfully")
            return result

        except Exception as e:
            self.logger.error(f"Error executing agent method: {str(e)}")
            raise

    @agent_interface(
        description="Get current status of the master agent",
        parameters={},
        returns="dict",
    )
    def get_status(self) -> dict[str, Any]:
        """Get current status of the master agent."""
        available_agents = self._get_agent_capabilities()

        return {
            "name": "MasterAgent",
            "status": "active",
            "model": self.effective_model,
            "model_provider": self.model_provider,
            "available_agents": len(available_agents),
            "agents": [agent["name"] for agent in available_agents],
            "timestamp": datetime.now().isoformat(),
        }
