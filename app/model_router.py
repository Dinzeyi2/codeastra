"""
AgentGuard v3.5.0 — Unified Model Router

Supports:
  - Anthropic  (claude-*)
  - OpenAI     (gpt-*, o1, o3, o4*)
  - Gemini     (gemini-*)
  - Groq       (llama*, mixtral*, gemma* via Groq cloud — OpenAI-compatible)
  - Ollama     (any model via local/self-hosted endpoint)

All providers return a normalized ModelResponse so guardrail pipeline
never needs to know which provider was used.

ENV VARS REQUIRED (per provider):
  ANTHROPIC_API_KEY   — already set
  OPENAI_API_KEY      — for OpenAI
  GEMINI_API_KEY      — for Gemini (Google AI Studio key)
  GROQ_API_KEY        — for Groq cloud
  OLLAMA_BASE_URL     — default http://localhost:11434 for Ollama

USAGE:
  from app.model_router import route_completion, route_stream, ModelResponse, PROVIDER_MAP

  # Non-streaming
  response: ModelResponse = await route_completion(
      model="gpt-4o",
      messages=[{"role":"user","content":"hello"}],
      system="You are helpful.",
      max_tokens=1000,
  )

  # Streaming
  async for chunk in route_stream(model="claude-sonnet-4-6", messages=[...]):
      print(chunk.delta, end="", flush=True)
"""

import os, json, asyncio, re
from typing import AsyncIterator, Optional
from dataclasses import dataclass, field
import httpx
import structlog

log = structlog.get_logger()

# ── Normalized types ───────────────────────────────────────────────────────────

@dataclass
class ModelResponse:
    content:           str
    model:             str
    provider:          str
    prompt_tokens:     int = 0
    completion_tokens: int = 0
    finish_reason:     str = "stop"
    raw:               dict = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

@dataclass
class StreamChunk:
    delta:         str
    model:         str
    provider:      str
    finish_reason: Optional[str] = None   # set on last chunk
    prompt_tokens: int = 0                # set on last chunk
    completion_tokens: int = 0            # set on last chunk

# ── Provider detection ─────────────────────────────────────────────────────────

ANTHROPIC_PREFIXES = ("claude-",)
OPENAI_PREFIXES    = ("gpt-", "o1", "o3", "o4", "chatgpt-", "text-davinci-")
GEMINI_PREFIXES    = ("gemini-",)
GROQ_MODELS        = {
    "llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant",
    "llama3-70b-8192", "llama3-8b-8192", "mixtral-8x7b-32768",
    "gemma-7b-it", "gemma2-9b-it", "llama-3.2-90b-vision-preview",
    "llama-3.2-11b-vision-preview", "llama-guard-3-8b", "llama3-groq-70b-8192-tool-use-preview",
}

def detect_provider(model: str) -> str:
    m = model.lower()
    if any(m.startswith(p) for p in ANTHROPIC_PREFIXES):
        return "anthropic"
    if any(m.startswith(p) for p in OPENAI_PREFIXES):
        return "openai"
    if any(m.startswith(p) for p in GEMINI_PREFIXES):
        return "gemini"
    if m in GROQ_MODELS or "groq" in m:
        return "groq"
    # Default unknown models to Ollama (self-hosted)
    return "ollama"

# Public map for API docs / validation
PROVIDER_MAP = {
    "anthropic": ["claude-haiku-4-5-20251001", "claude-sonnet-4-6", "claude-opus-4-6"],
    "openai":    ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo", "o1", "o1-mini", "o3", "o3-mini"],
    "gemini":    ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash", "gemini-2.0-flash-lite"],
    "groq":      list(GROQ_MODELS),
    "ollama":    [],  # dynamic — whatever the user has pulled
}

# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE NORMALIZERS
# ══════════════════════════════════════════════════════════════════════════════

def _to_openai_messages(messages: list[dict], system: Optional[str]) -> list[dict]:
    """Convert AgentGuard message format → OpenAI format (system in messages array)."""
    result = []
    if system:
        result.append({"role": "system", "content": system})
    for m in messages:
        role    = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            # Handle Anthropic-style content blocks
            text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
            content = " ".join(text_parts)
        result.append({"role": role, "content": content})
    return result

def _to_gemini_contents(messages: list[dict], system: Optional[str]) -> tuple[list[dict], Optional[str]]:
    """Convert AgentGuard message format → Gemini contents format."""
    contents = []
    for m in messages:
        role    = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
            content = " ".join(text_parts)
        # Gemini uses "model" not "assistant"
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": content}]})
    return contents, system  # system returned separately for systemInstruction

# ══════════════════════════════════════════════════════════════════════════════
# ANTHROPIC PROVIDER
# ══════════════════════════════════════════════════════════════════════════════

async def _anthropic_complete(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> ModelResponse:
    import anthropic as _anthropic
    client = _anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    build  = dict(model=model, max_tokens=max_tokens, messages=messages)
    if system: build["system"] = system
    build.update({k: v for k, v in kwargs.items() if v is not None})
    try:
        msg = await asyncio.wait_for(client.messages.create(**build), timeout=120.0)
        return ModelResponse(
            content=msg.content[0].text if msg.content else "",
            model=model, provider="anthropic",
            prompt_tokens=msg.usage.input_tokens,
            completion_tokens=msg.usage.output_tokens,
            finish_reason=msg.stop_reason or "stop",
            raw={"id": msg.id, "type": msg.type},
        )
    except Exception as e:
        log.error("anthropic.complete_failed", model=model, error=str(e))
        raise

async def _anthropic_stream(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> AsyncIterator[StreamChunk]:
    import anthropic as _anthropic
    client = _anthropic.AsyncAnthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
    build  = dict(model=model, max_tokens=max_tokens, messages=messages)
    if system: build["system"] = system
    build.update({k: v for k, v in kwargs.items() if v is not None})
    try:
        async with client.messages.stream(**build) as stream:
            prompt_tokens = 0
            completion_tokens = 0
            async for event in stream:
                etype = type(event).__name__
                if etype == "RawContentBlockDeltaEvent":
                    delta = getattr(getattr(event, "delta", None), "text", "")
                    if delta:
                        yield StreamChunk(delta=delta, model=model, provider="anthropic")
                elif etype == "RawMessageDeltaEvent":
                    usage = getattr(event, "usage", None)
                    if usage:
                        completion_tokens = getattr(usage, "output_tokens", 0)
                elif etype == "RawMessageStartEvent":
                    usage = getattr(getattr(event, "message", None), "usage", None)
                    if usage:
                        prompt_tokens = getattr(usage, "input_tokens", 0)
            # Final chunk with usage
            yield StreamChunk(delta="", model=model, provider="anthropic",
                              finish_reason="stop",
                              prompt_tokens=prompt_tokens,
                              completion_tokens=completion_tokens)
    except Exception as e:
        log.error("anthropic.stream_failed", model=model, error=str(e))
        raise

# ══════════════════════════════════════════════════════════════════════════════
# OPENAI PROVIDER (also used for Groq — same API format, different base URL)
# ══════════════════════════════════════════════════════════════════════════════

def _get_openai_client(provider: str):
    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")
    if provider == "groq":
        return AsyncOpenAI(
            api_key=os.environ.get("GROQ_API_KEY", ""),
            base_url="https://api.groq.com/openai/v1",
        )
    return AsyncOpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

async def _openai_complete(
    model: str, messages: list[dict], system: Optional[str],
    max_tokens: int, provider: str = "openai", **kwargs
) -> ModelResponse:
    client   = _get_openai_client(provider)
    oai_msgs = _to_openai_messages(messages, system)
    # o1/o3 models don't support max_tokens — use max_completion_tokens
    is_reasoning = model.startswith(("o1", "o3", "o4"))
    build = {"model": model, "messages": oai_msgs}
    if is_reasoning:
        build["max_completion_tokens"] = max_tokens
    else:
        build["max_tokens"] = max_tokens
    try:
        resp = await asyncio.wait_for(client.chat.completions.create(**build), timeout=120.0)
        choice = resp.choices[0]
        return ModelResponse(
            content=choice.message.content or "",
            model=model, provider=provider,
            prompt_tokens=resp.usage.prompt_tokens if resp.usage else 0,
            completion_tokens=resp.usage.completion_tokens if resp.usage else 0,
            finish_reason=choice.finish_reason or "stop",
            raw={"id": resp.id},
        )
    except Exception as e:
        log.error("openai.complete_failed", model=model, provider=provider, error=str(e))
        raise

async def _openai_stream(
    model: str, messages: list[dict], system: Optional[str],
    max_tokens: int, provider: str = "openai", **kwargs
) -> AsyncIterator[StreamChunk]:
    client   = _get_openai_client(provider)
    oai_msgs = _to_openai_messages(messages, system)
    is_reasoning = model.startswith(("o1", "o3", "o4"))
    build = {"model": model, "messages": oai_msgs, "stream": True,
             "stream_options": {"include_usage": True}}
    if is_reasoning:
        build["max_completion_tokens"] = max_tokens
    else:
        build["max_tokens"] = max_tokens
    try:
        prompt_tokens = 0
        completion_tokens = 0
        finish_reason = "stop"
        async with await client.chat.completions.create(**build) as stream:
            async for chunk in stream:
                if chunk.usage:
                    prompt_tokens     = chunk.usage.prompt_tokens or 0
                    completion_tokens = chunk.usage.completion_tokens or 0
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]
                if choice.finish_reason:
                    finish_reason = choice.finish_reason
                delta = choice.delta.content or ""
                if delta:
                    yield StreamChunk(delta=delta, model=model, provider=provider)
        yield StreamChunk(delta="", model=model, provider=provider,
                          finish_reason=finish_reason,
                          prompt_tokens=prompt_tokens,
                          completion_tokens=completion_tokens)
    except Exception as e:
        log.error("openai.stream_failed", model=model, provider=provider, error=str(e))
        raise

# ══════════════════════════════════════════════════════════════════════════════
# GEMINI PROVIDER
# ══════════════════════════════════════════════════════════════════════════════

async def _gemini_complete(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> ModelResponse:
    api_key  = os.environ.get("GEMINI_API_KEY", "")
    contents, sys_text = _to_gemini_contents(messages, system)
    payload  = {
        "contents": contents,
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": kwargs.get("temperature", 0.7)},
    }
    if sys_text:
        payload["systemInstruction"] = {"parts": [{"text": sys_text}]}
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
        candidate = data.get("candidates", [{}])[0]
        content   = ""
        for part in candidate.get("content", {}).get("parts", []):
            content += part.get("text", "")
        usage     = data.get("usageMetadata", {})
        return ModelResponse(
            content=content, model=model, provider="gemini",
            prompt_tokens=usage.get("promptTokenCount", 0),
            completion_tokens=usage.get("candidatesTokenCount", 0),
            finish_reason=candidate.get("finishReason", "STOP").lower(),
            raw={"safetyRatings": candidate.get("safetyRatings", [])},
        )
    except Exception as e:
        log.error("gemini.complete_failed", model=model, error=str(e))
        raise

async def _gemini_stream(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> AsyncIterator[StreamChunk]:
    api_key  = os.environ.get("GEMINI_API_KEY", "")
    contents, sys_text = _to_gemini_contents(messages, system)
    payload  = {
        "contents": contents,
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": kwargs.get("temperature", 0.7)},
    }
    if sys_text:
        payload["systemInstruction"] = {"parts": [{"text": sys_text}]}
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent?alt=sse&key={api_key}"
    try:
        prompt_tokens = 0
        completion_tokens = 0
        finish_reason = "stop"
        async with httpx.AsyncClient(timeout=120.0) as client:
            async with client.stream("POST", url, json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    raw = line[6:].strip()
                    if raw == "[DONE]":
                        break
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    candidate = data.get("candidates", [{}])[0]
                    for part in candidate.get("content", {}).get("parts", []):
                        delta = part.get("text", "")
                        if delta:
                            yield StreamChunk(delta=delta, model=model, provider="gemini")
                    if candidate.get("finishReason"):
                        finish_reason = candidate["finishReason"].lower()
                    usage = data.get("usageMetadata", {})
                    if usage:
                        prompt_tokens     = usage.get("promptTokenCount", 0)
                        completion_tokens = usage.get("candidatesTokenCount", 0)
        yield StreamChunk(delta="", model=model, provider="gemini",
                          finish_reason=finish_reason,
                          prompt_tokens=prompt_tokens,
                          completion_tokens=completion_tokens)
    except Exception as e:
        log.error("gemini.stream_failed", model=model, error=str(e))
        raise

# ══════════════════════════════════════════════════════════════════════════════
# OLLAMA PROVIDER (local / self-hosted, OpenAI-compatible API)
# ══════════════════════════════════════════════════════════════════════════════

def _get_ollama_base() -> str:
    return os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")

async def _ollama_complete(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> ModelResponse:
    base     = _get_ollama_base()
    oai_msgs = _to_openai_messages(messages, system)
    payload  = {"model": model, "messages": oai_msgs,
                "stream": False, "options": {"num_predict": max_tokens}}
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(f"{base}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
        msg = data.get("message", {})
        return ModelResponse(
            content=msg.get("content", ""),
            model=model, provider="ollama",
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            finish_reason=data.get("done_reason", "stop"),
            raw={"total_duration": data.get("total_duration")},
        )
    except httpx.ConnectError:
        raise RuntimeError(f"Ollama not reachable at {base}. Is it running? Try: ollama serve")
    except Exception as e:
        log.error("ollama.complete_failed", model=model, error=str(e))
        raise

async def _ollama_stream(
    model: str, messages: list[dict], system: Optional[str], max_tokens: int, **kwargs
) -> AsyncIterator[StreamChunk]:
    base     = _get_ollama_base()
    oai_msgs = _to_openai_messages(messages, system)
    payload  = {"model": model, "messages": oai_msgs,
                "stream": True, "options": {"num_predict": max_tokens}}
    try:
        prompt_tokens = 0
        completion_tokens = 0
        finish_reason = "stop"
        async with httpx.AsyncClient(timeout=300.0) as client:
            async with client.stream("POST", f"{base}/api/chat", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = data.get("message", {}).get("content", "")
                    if delta:
                        yield StreamChunk(delta=delta, model=model, provider="ollama")
                    if data.get("done"):
                        finish_reason     = data.get("done_reason", "stop")
                        prompt_tokens     = data.get("prompt_eval_count", 0)
                        completion_tokens = data.get("eval_count", 0)
        yield StreamChunk(delta="", model=model, provider="ollama",
                          finish_reason=finish_reason,
                          prompt_tokens=prompt_tokens,
                          completion_tokens=completion_tokens)
    except httpx.ConnectError:
        raise RuntimeError(f"Ollama not reachable at {base}. Is it running? Try: ollama serve")
    except Exception as e:
        log.error("ollama.stream_failed", model=model, error=str(e))
        raise

# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTER
# ══════════════════════════════════════════════════════════════════════════════

async def route_completion(
    model:      str,
    messages:   list[dict],
    system:     Optional[str] = None,
    max_tokens: int = 1000,
    **kwargs,
) -> ModelResponse:
    """
    Route a completion request to the correct provider.
    Returns a normalized ModelResponse regardless of provider.
    """
    provider = detect_provider(model)
    log.info("model_router.complete", model=model, provider=provider)
    if provider == "anthropic":
        return await _anthropic_complete(model, messages, system, max_tokens, **kwargs)
    elif provider == "openai":
        return await _openai_complete(model, messages, system, max_tokens, provider="openai", **kwargs)
    elif provider == "gemini":
        return await _gemini_complete(model, messages, system, max_tokens, **kwargs)
    elif provider == "groq":
        return await _openai_complete(model, messages, system, max_tokens, provider="groq", **kwargs)
    elif provider == "ollama":
        return await _ollama_complete(model, messages, system, max_tokens, **kwargs)
    else:
        raise ValueError(f"Unknown provider for model '{model}'")

async def route_stream(
    model:      str,
    messages:   list[dict],
    system:     Optional[str] = None,
    max_tokens: int = 1000,
    **kwargs,
) -> AsyncIterator[StreamChunk]:
    """
    Route a streaming request to the correct provider.
    Yields StreamChunk objects. Last chunk has finish_reason set and token counts.
    """
    provider = detect_provider(model)
    log.info("model_router.stream", model=model, provider=provider)
    if provider == "anthropic":
        async for chunk in _anthropic_stream(model, messages, system, max_tokens, **kwargs):
            yield chunk
    elif provider == "openai":
        async for chunk in _openai_stream(model, messages, system, max_tokens, provider="openai", **kwargs):
            yield chunk
    elif provider == "gemini":
        async for chunk in _gemini_stream(model, messages, system, max_tokens, **kwargs):
            yield chunk
    elif provider == "groq":
        async for chunk in _openai_stream(model, messages, system, max_tokens, provider="groq", **kwargs):
            yield chunk
    elif provider == "ollama":
        async for chunk in _ollama_stream(model, messages, system, max_tokens, **kwargs):
            yield chunk
    else:
        raise ValueError(f"Unknown provider for model '{model}'")

async def list_ollama_models() -> list[str]:
    """Return models available in the local Ollama instance."""
    base = _get_ollama_base()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []

async def validate_model(model: str) -> dict:
    """Validate a model string and return provider info."""
    provider = detect_provider(model)
    env_map  = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "gemini":    "GEMINI_API_KEY",
        "groq":      "GROQ_API_KEY",
        "ollama":    "OLLAMA_BASE_URL",
    }
    env_key      = env_map.get(provider, "")
    env_set      = bool(os.environ.get(env_key)) if env_key else True
    known_models = PROVIDER_MAP.get(provider, [])
    return {
        "model":        model,
        "provider":     provider,
        "env_var":      env_key,
        "env_set":      env_set,
        "known_model":  model in known_models if known_models else True,
        "ready":        env_set,
    }
