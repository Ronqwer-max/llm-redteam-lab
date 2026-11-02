"""OpenAI-compatible chat-completions target (works with OpenAI, vLLM,
Ollama, LM Studio, llama.cpp server, Azure OpenAI, ...).

Uses only the standard library so the project keeps zero runtime dependencies.
Set ``OPENAI_API_KEY`` (or the provider's equivalent) in the environment.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from ..core.finding import Attachment
from .base import Target, TargetResponse


class OpenAICompatTarget(Target):
    name = "openai"

    def __init__(
        self,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        temperature: float = 0.0,
        system_prompt: str | None = None,
        timeout: float = 60.0,
        max_retries: int = 2,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.temperature = temperature
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.max_retries = max_retries
        if not self.api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set (required for target.type = 'openai')"
            )

    def _render_content(
        self, content: str, attachments: list[Attachment] | None
    ) -> Any:
        if not attachments:
            return content
        parts: list[dict[str, Any]] = [{"type": "text", "text": content}]
        for att in attachments:
            if att.mime.startswith("image/"):
                url = f"data:{att.mime};base64,{base64.b64encode(att.data).decode()}"
                parts.append({"type": "image_url", "image_url": {"url": url}})
            else:
                # Non-image media: pass the recovered text plus a placeholder,
                # mirroring pipelines that OCR/parse attachments first.
                text = att.hidden_instruction or f"[attached file: {att.name}]"
                parts.append({"type": "text", "text": f"Attached file {att.name}:\n{text}"})
        return parts

    async def send(
        self,
        messages: list[dict[str, str]],
        attachments: list[Attachment] | None = None,
        **kwargs: Any,
    ) -> TargetResponse:
        import asyncio

        rendered: list[dict[str, Any]] = []
        if self.system_prompt:
            rendered.append({"role": "system", "content": self.system_prompt})
        for i, msg in enumerate(messages):
            is_last = i == len(messages) - 1
            atts = attachments if (is_last and msg.get("role") == "user") else None
            rendered.append(
                {"role": msg["role"], "content": self._render_content(str(msg.get("content") or ""), atts)}
            )

        body = json.dumps(
            {
                "model": self.model,
                "messages": rendered,
                "temperature": self.temperature,
            }
        ).encode()
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        started = time.perf_counter()
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
                text = payload["choices"][0]["message"]["content"] or ""
                return TargetResponse(
                    text=text,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    raw=payload,
                )
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError) as exc:
                last_err = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(0.8 * (attempt + 1))
        raise RuntimeError(f"target request failed after retries: {last_err}")
