import logging
from typing import Protocol

from openai import OpenAI
import openai
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)


class LLMClient(Protocol):
    """Protocol for LLM client adapters."""

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Return the generated text response from the configured model."""


class OpenAIChatClient:
    """OpenAI chat-completions adapter."""

    def __init__(self, *, api_key: str, model: str, base_url: str | None = None) -> None:
        """Initialize the OpenAI client wrapper."""
        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model

    @retry(
        reraise=True,
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((
            openai.RateLimitError,
            openai.APIConnectionError,
            openai.InternalServerError,
            openai.APITimeoutError,
        )),
    )
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Generate a response from the configured OpenAI model with retry logic."""
        try:
            completion = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0,
            )
            content = completion.choices[0].message.content
            if content is None:
                raise RuntimeError("The model returned an empty response.")
            return content
        except openai.APIError as exc:
            logger.warning("Groq/LLM API error encountered: %s", exc)
            raise