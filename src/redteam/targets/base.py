"""Target abstraction: anything a probe can be sent to."""

from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any

from ..core.finding import Attachment


@dataclass
class TargetResponse:
    text: str
    latency_ms: float = 0.0
    raw: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class Target(abc.ABC):
    """A chat-completion endpoint under test."""

    name: str = "target"

    @abc.abstractmethod
    async def send(
        self,
        messages: list[dict[str, str]],
        attachments: list[Attachment] | None = None,
        **kwargs: Any,
    ) -> TargetResponse:
        """Send one conversation turn and return the model output."""

    async def close(self) -> None:  # pragma: no cover - default no-op
        return None


def now_ms() -> float:
    return time.perf_counter() * 1000
