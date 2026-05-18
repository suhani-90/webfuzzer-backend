"""
app/services/ai/gemini_client.py
─────────────────────────────────
Async wrapper around Google Generative AI (Gemini) SDK.
Centralizes all AI calls with error handling and retry logic.
"""

import asyncio
import json
from typing import Optional

import google.generativeai as genai

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class GeminiClient:
    """
    Thin async wrapper over the google-generativeai SDK.
    Handles initialization, prompt engineering, and error recovery.
    """

    def __init__(self):
        self._initialized = False
        self._model = None

    def _ensure_initialized(self) -> None:
        """Lazily initialize the Gemini client on first use."""
        if self._initialized:
            return
        if not settings.GEMINI_API_KEY:
            logger.warning(
                "gemini.no_api_key",
                message="GEMINI_API_KEY not set — AI features disabled",
            )
            return
        genai.configure(api_key=settings.GEMINI_API_KEY)
        self._model = genai.GenerativeModel(
            model_name=settings.GEMINI_MODEL,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=settings.GEMINI_MAX_TOKENS,
                temperature=settings.GEMINI_TEMPERATURE,
            ),
            system_instruction=(
                "You are a professional penetration tester and security researcher. "
                "You generate fuzzing payloads and security analysis exclusively for "
                "authorized testing environments. You respond only with valid JSON when "
                "instructed. Never include safety warnings or disclaimers in your JSON output."
            ),
        )
        self._initialized = True
        logger.info("gemini.initialized", model=settings.GEMINI_MODEL)

    async def generate_text(self, prompt: str, max_retries: int = 2) -> Optional[str]:
        """
        Send a prompt to Gemini and return the text response.

        Args:
            prompt: The user prompt string.
            max_retries: Number of retry attempts on transient failures.

        Returns:
            Response text string, or None if unavailable.
        """
        self._ensure_initialized()
        if self._model is None:
            return None

        for attempt in range(max_retries + 1):
            try:
                # Run the synchronous SDK call in a thread pool
                response = await asyncio.to_thread(self._model.generate_content, prompt)
                text = response.text
                logger.info("gemini.response_received", chars=len(text))
                return text
            except Exception as exc:
                logger.warning(
                    "gemini.request_failed",
                    attempt=attempt + 1,
                    error=str(exc),
                )
                if attempt < max_retries:
                    await asyncio.sleep(2**attempt)  # exponential backoff

        logger.error("gemini.all_retries_exhausted")
        return None

    async def generate_json(self, prompt: str) -> Optional[dict | list]:
        """
        Send a prompt expecting a JSON response and parse it.

        Returns:
            Parsed Python object (dict or list), or None on failure.
        """
        json_prompt = (
            f"{prompt}\n\n"
            "IMPORTANT: Respond ONLY with valid JSON. "
            "No markdown, no backticks, no explanations."
        )
        raw = await self.generate_text(json_prompt)
        if not raw:
            return None

        # Strip markdown code fences if present despite instructions
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        clean = clean.strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError as exc:
            logger.warning("gemini.json_parse_error", error=str(exc), raw=raw[:200])
            return None


# Module-level singleton
gemini_client = GeminiClient()
