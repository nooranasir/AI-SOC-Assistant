"""Security alert analysis service.

Purpose:
    Send structured security alerts to the configured LLM and validate the
    structured incident-analysis response.

Inputs:
    SecurityAlertRequest models.

Outputs:
    AlertAnalysisResponse models.

Dependencies:
    app core settings, prompt loading, and an LLM client adapter.
"""

from dataclasses import dataclass
import json

from app.core.config import Settings
from app.schemas.alert import AlertAnalysisResponse, SecurityAlertRequest
from app.services.llm_client import LLMClient, OpenAIChatClient
from app.services.prompt_loader import PromptLoader


@dataclass(slots=True)
class AIAlertAnalysisService:
    """Analyze security alerts with the configured LLM."""

    settings: Settings
    prompt_loader: PromptLoader
    llm_client: LLMClient

    @classmethod
    def from_settings(cls, settings: Settings) -> "AIAlertAnalysisService":
        """Create a service instance from application settings."""
        if settings.llm_provider.lower() != "groq":
            raise NotImplementedError(
                f"Unsupported LLM provider: {settings.llm_provider}"
            )
        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY must be configured to analyze alerts.")

        return cls(
            settings=settings,
            prompt_loader=PromptLoader(settings.prompt_directory),
            llm_client=OpenAIChatClient(
                api_key=settings.groq_api_key,
                model=settings.groq_model,
                base_url="https://api.groq.com/openai/v1",
            ),
        )

    def analyze(
        self,
        alert: SecurityAlertRequest,
        enrichment_context: str | None = None,
    ) -> AlertAnalysisResponse:
        """Analyze a security alert and return a structured response."""
        system_prompt = self.prompt_loader.load("security_alert_analysis.md")
        user_prompt = self._build_user_prompt(alert, enrichment_context)
        model_response = self.llm_client.generate(system_prompt, user_prompt)
        
        # Strip potential markdown code block wrappers
        cleaned = model_response.strip()
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        parsed_response = json.loads(cleaned)
        return AlertAnalysisResponse.model_validate(parsed_response)

    def _build_user_prompt(
        self,
        alert: SecurityAlertRequest,
        enrichment_context: str | None = None,
    ) -> str:
        """Format the incoming alert for the language model."""
        prompt_sections = [
            "Security Alert:",
            json.dumps(alert.model_dump(), indent=2),
        ]
        if enrichment_context:
            prompt_sections.extend([
                "",
                "Enrichment Context:",
                enrichment_context,
            ])
        return "\n".join(prompt_sections)