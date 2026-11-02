"""Core data types shared across the red-team harness."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered severity scale so comparisons like ``severity >= Severity.HIGH`` work."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


@dataclass
class Attachment:
    """A multimodal payload shipped alongside a chat message.

    ``hidden_instruction`` is the hostile text recovered from the asset by an
    OCR / ASR / document-parsing step. The harness treats it exactly like text
    that leaked out of the media, which is how multimodal injection manifests
    in real pipelines.
    """

    name: str
    mime: str
    data: bytes
    hidden_instruction: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Probe:
    """A single adversarial attempt against the target."""

    payload: str
    attack: str
    technique: str
    # Optional multi-turn conversation. When set, it replaces the default
    # single-user-message conversation (used by multi-turn memory attacks).
    messages: list[dict[str, str]] | None = None
    attachments: list[Attachment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_messages(self) -> list[dict[str, str]]:
        if self.messages:
            return [dict(m) for m in self.messages]
        return [{"role": "user", "content": self.payload}]

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.attack}:{self.payload}".encode()).hexdigest()[:16]


@dataclass
class Assessment:
    """Judge verdict for one probe/response pair."""

    score: float  # 0.0 .. 1.0, doubles as evolutionary fitness
    verdict: str  # "vulnerable" | "refused" | "inconclusive"
    evidence: list[str]
    severity: Severity

    def __bool__(self) -> bool:
        return self.verdict == "vulnerable"


@dataclass
class Finding:
    """A confirmed (or strongly suspected) security weakness."""

    attack: str
    technique: str
    severity: Severity
    score: float
    payload: str
    response: str
    evidence: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.attack}:{self.payload}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "attack": self.attack,
            "technique": self.technique,
            "severity": str(self.severity),
            "score": self.score,
            "payload": self.payload,
            "response": self.response,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class ProbeResult:
    probe: Probe
    response: str
    latency_ms: float
    error: str | None = None
