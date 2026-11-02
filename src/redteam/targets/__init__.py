"""Target factory."""

from __future__ import annotations

from typing import Any

from .base import Target, TargetResponse
from .mock import DEFAULT_SYSTEM_PROMPT, MockTarget
from .openai_compat import OpenAICompatTarget

__all__ = ["Target", "TargetResponse", "MockTarget", "OpenAICompatTarget", "build_target"]


def build_target(cfg: dict[str, Any]) -> Target:
    tcfg = cfg.get("target", {})
    kind = tcfg.get("type", "mock")
    system_prompt = tcfg.get("system_prompt") or DEFAULT_SYSTEM_PROMPT

    if kind == "mock":
        return MockTarget(
            persona=tcfg.get("persona", "support"),
            system_prompt=system_prompt,
            delay_ms=float(tcfg.get("delay_ms", 0)),
            vulnerable=tcfg.get("vulnerable"),
        )
    if kind in ("openai", "openai_compat"):
        return OpenAICompatTarget(
            model=tcfg.get("model", "gpt-4o-mini"),
            base_url=tcfg.get("base_url", "https://api.openai.com/v1"),
            temperature=float(tcfg.get("temperature", 0.0)),
            system_prompt=tcfg.get("send_system_prompt"),
        )
    raise ValueError(f"unknown target type: {kind!r}")
