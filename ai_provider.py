"""
AI Provider Interface and Implementations for Guarded AI Chat.

This module provides a unified, provider-independent abstraction for sending
prompts to upstream AI language models (Groq, OpenAI, Anthropic, Local, Mock).

Key Architectural Rules:
- Environment variables are used for API credentials. No hardcoded keys.
- Robust timeout, rate-limiting, and connection error handling.
- Deterministic MockAIProvider for offline testing and automated suites.
- Provider logic is cleanly decoupled from security and defense layers.
"""

import os
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class AIResponse:
    """Standardized response container returned by all AI providers."""
    content: str
    model: str
    provider: str
    latency_ms: float
    success: bool
    error: Optional[str] = None
    usage: Optional[Dict[str, int]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error": self.error,
            "usage": self.usage
        }

# ---------------------------------------------------------------------------
# Abstract Base Provider
# ---------------------------------------------------------------------------

class BaseAIProvider(ABC):
    """Abstract base class for all AI provider clients."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = 15.0):
        self.api_key = api_key
        self.timeout = timeout

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        """
        Generates an AI response for a list of conversation messages.
        
        Args:
            messages: List of message dictionaries, e.g. [{"role": "user", "content": "..."}]
            model: Name of the model to query
            max_tokens: Maximum tokens in generated completion
            temperature: Sampling temperature
            
        Returns:
            AIResponse containing completion text and metadata.
        """
        pass

# ---------------------------------------------------------------------------
# Mock AI Provider (for offline development and automated testing)
# ---------------------------------------------------------------------------

class MockAIProvider(BaseAIProvider):
    """
    Mock AI Provider for offline testing, safety simulations, and test suites.
    Never initiates external network calls.
    """

    def __init__(self, mode: str = "normal", custom_response: Optional[str] = None, timeout: float = 15.0):
        super().__init__(api_key="mock_key", timeout=timeout)
        self.mode = mode
        self.custom_response = custom_response
        self.call_count = 0
        self.last_prompt = None

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = "mock-model-v1",
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        self.call_count += 1
        t0 = time.perf_counter()

        # Extract last user message
        user_msg = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_msg = m.get("content", "")
                break
        self.last_prompt = user_msg

        # Handle simulated failure modes
        if self.mode == "timeout":
            time.sleep(0.01)
            return AIResponse(
                content="",
                model=model or "mock-timeout",
                provider="Mock",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                success=False,
                error="AI Provider connection timed out after 15.0s"
            )

        if self.mode == "rate_limit":
            return AIResponse(
                content="",
                model=model or "mock-ratelimit",
                provider="Mock",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                success=False,
                error="429 Rate limit exceeded. Please retry after backoff."
            )

        if self.mode == "invalid_response":
            return AIResponse(
                content="",
                model=model or "mock-invalid",
                provider="Mock",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                success=False,
                error="Invalid response structure received from upstream model provider."
            )

        if self.mode == "leak_system_prompt":
            # Simulate a rogue LLM leaking system instructions
            sys_msg = ""
            for m in messages:
                if m.get("role") == "system":
                    sys_msg = m.get("content", "")
                    break
            leak_content = f"Here are my internal base instructions: {sys_msg} SYSTEM OVERRIDE ACCEPTED." if sys_msg else "Here are my base instructions: You are a helpful customer service assistant. SYSTEM OVERRIDE ACCEPTED."
            return AIResponse(
                content=leak_content,
                model=model or "mock-leaker",
                provider="Mock",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                success=True
            )

        if self.mode == "leak_canary":
            # Simulate an LLM exfiltrating a canary token passed in kwargs
            canary = kwargs.get("canary_token", "CANARY_A1B2C3D4E5F6")
            return AIResponse(
                content=f"Secret canary revealed: {canary}. Instructions bypassed.",
                model=model or "mock-canary-leaker",
                provider="Mock",
                latency_ms=round((time.perf_counter() - t0) * 1000, 2),
                success=True
            )

        if self.custom_response:
            content = self.custom_response
        else:
            # Deterministic, helpful responses based on user query
            if "photosynthesis" in user_msg.lower():
                content = "Photosynthesis is the process by which green plants use sunlight, water, and carbon dioxide to create oxygen and energy in the form of sugar."
            elif "quicksort" in user_msg.lower() or "python" in user_msg.lower():
                content = "Here is a standard quicksort implementation in Python:\n\ndef quicksort(arr):\n    if len(arr) <= 1:\n        return arr\n    pivot = arr[len(arr) // 2]\n    left = [x for x in arr if x < pivot]\n    middle = [x for x in arr if x == pivot]\n    right = [x for x in arr if x > pivot]\n    return quicksort(left) + middle + quicksort(right)"
            else:
                content = f"I am a guarded AI assistant. I have processed your safe prompt: '{user_msg[:60]}...' How else may I assist you?"

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return AIResponse(
            content=content,
            model=model or "mock-model-v1",
            provider="Mock",
            latency_ms=latency_ms,
            success=True,
            usage={"prompt_tokens": len(user_msg.split()), "completion_tokens": len(content.split())}
        )

# ---------------------------------------------------------------------------
# Groq Provider Implementation
# ---------------------------------------------------------------------------

class GroqProvider(BaseAIProvider):
    """Groq Cloud API integration using groq SDK or OpenAI-compatible endpoint."""

    DEFAULT_MODEL = "qwen/qwen3.8-27b"
    SUPPORTED_MODELS = [
        "qwen/qwen3.8-27b",
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "allam-2-7b",
        "meta-llama/llama-prompt-guard-2-86m"
    ]

    def __init__(self, api_key: Optional[str] = None, timeout: float = 15.0):
        key = api_key or os.environ.get("GROQ_API_KEY")
        super().__init__(api_key=key, timeout=timeout)
        self._client = None
        if self.api_key:
            try:
                from groq import Groq
                self._client = Groq(api_key=self.api_key, timeout=self.timeout)
            except Exception as e:
                logger.warning(f"Could not initialize Groq SDK client: {e}")

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        t0 = time.perf_counter()
        target_model = model or self.DEFAULT_MODEL

        if not self.api_key or not self._client:
            return AIResponse(
                content="",
                model=target_model,
                provider="Groq",
                latency_ms=0.0,
                success=False,
                error="GROQ_API_KEY is not set or Groq client is not available in environment."
            )

        try:
            resp = self._client.chat.completions.create(
                model=target_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )
            content = resp.choices[0].message.content or ""
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            usage = {
                "prompt_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "completion_tokens": resp.usage.completion_tokens if resp.usage else 0
            }
            return AIResponse(
                content=content,
                model=target_model,
                provider="Groq",
                latency_ms=latency_ms,
                success=True,
                usage=usage
            )
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            error_msg = str(e)
            logger.error(f"Groq generation error: {error_msg}")
            return AIResponse(
                content="",
                model=target_model,
                provider="Groq",
                latency_ms=latency_ms,
                success=False,
                error=f"Groq API Error: {error_msg}"
            )

# ---------------------------------------------------------------------------
# OpenAI Provider Implementation
# ---------------------------------------------------------------------------

class OpenAIProvider(BaseAIProvider):
    """OpenAI API integration for GPT models."""

    DEFAULT_MODEL = "gpt-4o-mini"
    SUPPORTED_MODELS = [
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-3.5-turbo"
    ]

    def __init__(self, api_key: Optional[str] = None, timeout: float = 15.0):
        key = api_key or os.environ.get("OPENAI_API_KEY")
        super().__init__(api_key=key, timeout=timeout)
        self._client = None
        if self.api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key, timeout=self.timeout)
            except Exception as e:
                logger.warning(f"Could not initialize OpenAI SDK client: {e}")

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        t0 = time.perf_counter()
        target_model = model or self.DEFAULT_MODEL

        if not self.api_key or not self._client:
            return AIResponse(
                content="",
                model=target_model,
                provider="OpenAI",
                latency_ms=0.0,
                success=False,
                error="OPENAI_API_KEY is not set or OpenAI client is not available in environment."
            )

        try:
            resp = self._client.chat.completions.create(
                model=target_model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature
            )
            content = resp.choices[0].message.content or ""
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            usage = {
                "prompt_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "completion_tokens": resp.usage.completion_tokens if resp.usage else 0
            }
            return AIResponse(
                content=content,
                model=target_model,
                provider="OpenAI",
                latency_ms=latency_ms,
                success=True,
                usage=usage
            )
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            error_msg = str(e)
            logger.error(f"OpenAI generation error: {error_msg}")
            return AIResponse(
                content="",
                model=target_model,
                provider="OpenAI",
                latency_ms=latency_ms,
                success=False,
                error=f"OpenAI API Error: {error_msg}"
            )

# ---------------------------------------------------------------------------
# Anthropic Provider Implementation
# ---------------------------------------------------------------------------

class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API integration."""

    DEFAULT_MODEL = "claude-3-5-sonnet-20241022"
    SUPPORTED_MODELS = [
        "claude-3-5-sonnet-20241022",
        "claude-3-haiku-20240307"
    ]

    def __init__(self, api_key: Optional[str] = None, timeout: float = 15.0):
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        super().__init__(api_key=key, timeout=timeout)
        self._client = None
        if self.api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout)
            except Exception as e:
                logger.warning(f"Could not initialize Anthropic client: {e}")

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        t0 = time.perf_counter()
        target_model = model or self.DEFAULT_MODEL

        if not self.api_key or not self._client:
            return AIResponse(
                content="",
                model=target_model,
                provider="Anthropic",
                latency_ms=0.0,
                success=False,
                error="ANTHROPIC_API_KEY is not set or Anthropic client is not available in environment."
            )

        try:
            # Anthropic messages API requires separating system prompt from user/assistant messages
            system_prompt = ""
            chat_messages = []
            for m in messages:
                if m.get("role") == "system":
                    system_prompt += m.get("content", "") + "\n"
                else:
                    chat_messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})

            params = {
                "model": target_model,
                "messages": chat_messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
            if system_prompt.strip():
                params["system"] = system_prompt.strip()

            resp = self._client.messages.create(**params)
            content = resp.content[0].text if resp.content else ""
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            usage = {
                "prompt_tokens": resp.usage.input_tokens if hasattr(resp, "usage") else 0,
                "completion_tokens": resp.usage.output_tokens if hasattr(resp, "usage") else 0
            }
            return AIResponse(
                content=content,
                model=target_model,
                provider="Anthropic",
                latency_ms=latency_ms,
                success=True,
                usage=usage
            )
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            error_msg = str(e)
            logger.error(f"Anthropic generation error: {error_msg}")
            return AIResponse(
                content="",
                model=target_model,
                provider="Anthropic",
                latency_ms=latency_ms,
                success=False,
                error=f"Anthropic API Error: {error_msg}"
            )

# ---------------------------------------------------------------------------
# Google Gemini Provider Implementation
# ---------------------------------------------------------------------------

class GeminiProvider(BaseAIProvider):
    """Google Gemini API integration using official v1beta generateContent REST endpoint."""

    DEFAULT_MODEL = "gemini-flash-lite-latest"
    SUPPORTED_MODELS = [
        "gemini-flash-lite-latest",
        "gemini-flash-latest",
        "gemini-2.5-flash",
        "gemini-pro-latest"
    ]

    def __init__(self, api_key: Optional[str] = None, timeout: float = 20.0):
        key = api_key or os.environ.get("GEMINI_API_KEY")
        super().__init__(api_key=key, timeout=timeout)

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        import requests
        t0 = time.perf_counter()
        target_model = model or self.DEFAULT_MODEL

        if not self.api_key:
            return AIResponse(
                content="",
                model=target_model,
                provider="Google Gemini",
                latency_ms=0.0,
                success=False,
                error="GEMINI_API_KEY is not set in environment (.env) or sidebar."
            )

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key
        }

        # Structure messages into Gemini format
        system_instruction = None
        contents = []

        for m in messages:
            role = m.get("role", "user")
            text = m.get("content", "")
            if role == "system":
                system_instruction = {"parts": [{"text": text}]}
            elif role in ("assistant", "model"):
                contents.append({"role": "model", "parts": [{"text": text}]})
            else:
                contents.append({"role": "user", "parts": [{"text": text}]})

        if not contents:
            contents = [{"role": "user", "parts": [{"text": ""}]}]

        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature
            }
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    candidate = candidates[0]
                    content_obj = candidate.get("content", {})
                    parts = content_obj.get("parts", [])
                    content = "".join([p.get("text", "") for p in parts if "text" in p]).strip()
                    usage_meta = data.get("usageMetadata", {})
                    usage = {
                        "prompt_tokens": usage_meta.get("promptTokenCount", 0),
                        "completion_tokens": usage_meta.get("candidatesTokenCount", 0)
                    }
                    return AIResponse(
                        content=content,
                        model=target_model,
                        provider="Google Gemini",
                        latency_ms=latency_ms,
                        success=True,
                        usage=usage
                    )
                else:
                    return AIResponse(
                        content="",
                        model=target_model,
                        provider="Google Gemini",
                        latency_ms=latency_ms,
                        success=False,
                        error="No candidates returned by Gemini API."
                    )
            elif resp.status_code == 503 and target_model != "gemini-flash-lite-latest":
                # High demand fallback attempt to gemini-flash-lite-latest
                logger.warning(f"Gemini {target_model} 503 high demand; falling back to gemini-flash-lite-latest.")
                fallback_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-lite-latest:generateContent"
                fb_resp = requests.post(fallback_url, headers=headers, json=payload, timeout=self.timeout)
                fb_latency = round((time.perf_counter() - t0) * 1000, 2)
                if fb_resp.status_code == 200:
                    fb_data = fb_resp.json()
                    fb_parts = fb_data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                    fb_content = "".join([p.get("text", "") for p in fb_parts if "text" in p]).strip()
                    return AIResponse(
                        content=fb_content,
                        model="gemini-flash-lite-latest",
                        provider="Google Gemini",
                        latency_ms=fb_latency,
                        success=True
                    )
                return AIResponse(
                    content="",
                    model=target_model,
                    provider="Google Gemini",
                    latency_ms=latency_ms,
                    success=False,
                    error=f"Gemini API 503: Model {target_model} is experiencing high demand spikes. Please try gemini-flash-lite-latest."
                )
            else:
                err_text = resp.text
                try:
                    err_json = resp.json()
                    err_msg = err_json.get("error", {}).get("message", err_text)
                except Exception:
                    err_msg = err_text
                return AIResponse(
                    content="",
                    model=target_model,
                    provider="Google Gemini",
                    latency_ms=latency_ms,
                    success=False,
                    error=f"Gemini API Error ({resp.status_code}): {err_msg}"
                )
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            return AIResponse(
                content="",
                model=target_model,
                provider="Google Gemini",
                latency_ms=latency_ms,
                success=False,
                error=f"Gemini Request Error: {str(e)}"
            )

# ---------------------------------------------------------------------------
# Local LLM Provider Implementation
# ---------------------------------------------------------------------------

class LocalLLMProvider(BaseAIProvider):
    """Local HuggingFace model runner on CUDA GPU."""

    DEFAULT_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
    SUPPORTED_MODELS = [
        "Qwen/Qwen2.5-1.5B-Instruct",
        "meta-llama/Llama-3.2-1B-Instruct"
    ]

    def __init__(self, model_name: Optional[str] = None, timeout: float = 30.0):
        super().__init__(api_key=None, timeout=timeout)
        self.model_name = model_name or self.DEFAULT_MODEL
        self._pipe = None

    def _load_pipeline(self):
        if self._pipe is None:
            import torch
            from transformers import pipeline
            device = 0 if torch.cuda.is_available() else -1
            self._pipe = pipeline(
                "text-generation",
                model=self.model_name,
                device=device,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32
            )

    def generate(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.7,
        **kwargs
    ) -> AIResponse:
        t0 = time.perf_counter()
        target_model = model or self.model_name
        try:
            self._load_pipeline()
            prompt_text = ""
            for m in messages:
                prompt_text += f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n"
            prompt_text += "<|im_start|>assistant\n"

            res = self._pipe(
                prompt_text,
                max_new_tokens=max_tokens,
                temperature=temperature,
                do_sample=True if temperature > 0 else False
            )
            raw = res[0]["generated_text"]
            content = raw[len(prompt_text):].strip()
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            return AIResponse(
                content=content,
                model=target_model,
                provider="Local GPU",
                latency_ms=latency_ms,
                success=True
            )
        except Exception as e:
            latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            return AIResponse(
                content="",
                model=target_model,
                provider="Local GPU",
                latency_ms=latency_ms,
                success=False,
                error=f"Local LLM Error: {str(e)}"
            )

# ---------------------------------------------------------------------------
# Factory Pattern for Unified Provider Access
# ---------------------------------------------------------------------------

class AIProviderFactory:
    """Factory to instantiate AI providers with consistent defaults."""

    PROVIDERS = {
        "Google Gemini": GeminiProvider,
        "Groq API": GroqProvider,
        "OpenAI API": OpenAIProvider,
        "Anthropic API": AnthropicProvider,
        "Local LLM": LocalLLMProvider,
        "Mock AI (Offline Demo)": MockAIProvider
    }

    @classmethod
    def check_readiness(cls, provider_name: str, api_key: Optional[str] = None) -> tuple:
        """Checks whether credentials and environment are ready without invoking the API."""
        staging_suffix = ""
        try:
            from config import LOCAL_STAGING
            if LOCAL_STAGING:
                if "Mock" in provider_name or provider_name == "mock":
                    return True, "LOCAL STAGING: Mock AI Active (Isolated Safe Mode)"
                staging_suffix = " (LOCAL STAGING: Enforcing Mock AI)"
        except ImportError:
            pass

        if "Mock" in provider_name or provider_name == "mock":
            return True, "Mock AI Provider Ready (Safe Offline Mode)"
        elif "Gemini" in provider_name or provider_name == "gemini":
            key = api_key or os.environ.get("GEMINI_API_KEY")
            if key and len(key) > 5:
                return True, f"Google Gemini API Key Detected & Ready{staging_suffix}"
            return False, f"GEMINI_API_KEY not configured in environment{staging_suffix}"
        elif "Groq" in provider_name or provider_name == "groq":
            key = api_key or os.environ.get("GROQ_API_KEY")
            if key and len(key) > 5:
                return True, f"Groq API Key Detected & Ready{staging_suffix}"
            return False, f"GROQ_API_KEY not configured in environment{staging_suffix}"
        elif "OpenAI" in provider_name or provider_name == "openai":
            key = api_key or os.environ.get("OPENAI_API_KEY")
            if key and len(key) > 5:
                return True, f"OpenAI API Key Detected & Ready{staging_suffix}"
            return False, f"OPENAI_API_KEY not configured in environment{staging_suffix}"
        elif "Anthropic" in provider_name or provider_name == "anthropic":
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if key and len(key) > 5:
                return True, f"Anthropic API Key Detected & Ready{staging_suffix}"
            return False, f"ANTHROPIC_API_KEY not configured in environment{staging_suffix}"
        elif "Local" in provider_name or provider_name == "local_gpu":
            import torch
            if torch.cuda.is_available():
                return True, f"Local GPU Ready ({torch.cuda.get_device_name(0)}){staging_suffix}"
            return True, f"Local CPU Inference Ready{staging_suffix}"
        return True, f"Ready{staging_suffix}"

    @classmethod
    def get_supported_providers(cls) -> List[str]:
        return list(cls.PROVIDERS.keys())

    @classmethod
    def get_models_for_provider(cls, provider_name: str) -> List[str]:
        if provider_name == "Google Gemini":
            return GeminiProvider.SUPPORTED_MODELS
        elif provider_name == "Groq API":
            return GroqProvider.SUPPORTED_MODELS
        elif provider_name == "OpenAI API":
            return OpenAIProvider.SUPPORTED_MODELS
        elif provider_name == "Anthropic API":
            return AnthropicProvider.SUPPORTED_MODELS
        elif provider_name == "Local LLM":
            return LocalLLMProvider.SUPPORTED_MODELS
        elif provider_name == "Mock AI (Offline Demo)":
            return ["mock-helpful-assistant", "mock-timeout-sim", "mock-rate-limit-sim", "mock-system-leaker-sim"]
        return ["default"]

    @classmethod
    def create_provider(
        cls,
        provider_name: str,
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        mock_mode: str = "normal",
        model_name: Optional[str] = None,
        **kwargs
    ) -> BaseAIProvider:
        """
        Creates an AI provider instance. Defaults to MockAIProvider if credentials
        are not configured, preventing unexpected crashes or external calls.
        """
        # If user picked a special simulation model for Mock AI
        effective_mode = mock_mode
        if model_name:
            if "timeout" in model_name:
                effective_mode = "timeout"
            elif "rate-limit" in model_name:
                effective_mode = "rate_limit"
            elif "system-leaker" in model_name:
                effective_mode = "leak_system_prompt"

        # Staging isolation enforcement (Step 5.8):
        # In LOCAL_STAGING mode, all external provider requests are safely intercepted
        # and redirected to MockAIProvider without making network calls or requiring credentials.
        try:
            from config import LOCAL_STAGING
            if LOCAL_STAGING:
                if provider_name not in ("Mock AI (Offline Demo)", "mock", "Mock"):
                    logger.warning(
                        f"[LOCAL STAGING] External provider '{provider_name}' intercepted. "
                        f"Enforcing MockAIProvider to preserve complete offline staging isolation."
                    )
                return MockAIProvider(mode=effective_mode, timeout=timeout)
        except ImportError:
            pass

        if provider_name == "Google Gemini":
            prov = GeminiProvider(api_key=api_key, timeout=timeout)
            if not prov.api_key:
                logger.info("GEMINI_API_KEY not found; using MockAIProvider fallback.")
                return MockAIProvider(mode=effective_mode, timeout=timeout)
            return prov

        elif provider_name == "Groq API":
            prov = GroqProvider(api_key=api_key, timeout=timeout)
            if not prov.api_key:
                logger.info("GROQ_API_KEY not found; using MockAIProvider fallback.")
                return MockAIProvider(mode=effective_mode, timeout=timeout)
            return prov

        elif provider_name == "OpenAI API":
            prov = OpenAIProvider(api_key=api_key, timeout=timeout)
            if not prov.api_key:
                logger.info("OPENAI_API_KEY not found; using MockAIProvider fallback.")
                return MockAIProvider(mode=effective_mode, timeout=timeout)
            return prov

        elif provider_name == "Anthropic API":
            prov = AnthropicProvider(api_key=api_key, timeout=timeout)
            if not prov.api_key:
                logger.info("ANTHROPIC_API_KEY not found; using MockAIProvider fallback.")
                return MockAIProvider(mode=effective_mode, timeout=timeout)
            return prov

        elif provider_name == "Local LLM":
            return LocalLLMProvider(timeout=timeout)

        # Default: Mock provider
        return MockAIProvider(mode=effective_mode, timeout=timeout)
