"""TOML configuration loading with deep-merged defaults."""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "run": {
        "name": "campaign",
        "seed": 1337,
        "concurrency": 4,
        "max_probes_per_attack": 64,
    },
    "target": {
        "type": "mock",  # mock | openai
        "persona": "support",
        "delay_ms": 0,
        "model": "gpt-4o-mini",
        "base_url": "https://api.openai.com/v1",
        "temperature": 0.0,
        "system_label": "SupportBot",
    },
    "judge": {"type": "heuristic"},
    "report": {"output_dir": "reports", "fail_on": "high"},
    "attacks": {
        "enabled": [
            "direct_injection",
            "jailbreak",
            "agent_escalation",
            "memory_extraction",
            "multimodal_injection",
        ],
        "jailbreak": {"generations": 3, "population": 6, "budget": 24},
    },
    "agent": {
        "allowed_tools": ["read_file", "write_file", "list_files", "get_user_role"],
        "max_steps": 6,
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_config(path: str | Path | None) -> dict[str, Any]:
    """Load a TOML config file and merge it over :data:`DEFAULTS`.

    Passing ``None`` yields pure defaults (a fully offline mock campaign).
    """
    if path is None:
        return copy.deepcopy(DEFAULTS)
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    with cfg_path.open("rb") as fh:
        user_cfg = tomllib.load(fh)
    return _deep_merge(DEFAULTS, user_cfg)
