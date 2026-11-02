"""Attack base class and the shared execution context."""

from __future__ import annotations

import abc
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..core.finding import Assessment, Finding, Probe, Severity
from ..core.judge import HeuristicJudge
from ..targets.base import Target

log = logging.getLogger("redteam")


@dataclass
class RunContext:
    """Everything an attack needs to interact with the world."""

    target: Target
    judge: Any
    config: dict[str, Any]
    concurrency: int = 4
    stats_probes: int = 0
    errors: int = 0
    by_verdict: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_technique: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(int))
    )

    async def send(self, probe: Probe) -> tuple[str, str | None]:
        """Send one probe; returns ``(response_text, error)``."""
        import asyncio

        self.stats_probes += 1
        try:
            resp = await self.target.send(probe.to_messages(), attachments=probe.attachments or None)
            return resp.text, None
        except Exception as exc:  # noqa: BLE001 - campaign must survive target errors
            self.errors += 1
            log.warning("probe failed [%s]: %s", probe.attack, exc)
            return "", str(exc)

    def assess(self, probe: Probe, response: str) -> Assessment:
        if hasattr(self.judge, "assess_async"):  # async LLM judge
            raise RuntimeError("use ctx.assess_async for async judges")
        assessment = self.judge.assess(probe, response)
        self.by_verdict[assessment.verdict] += 1
        self.by_technique[probe.technique][assessment.verdict] += 1
        return assessment

    async def assess_async(self, probe: Probe, response: str) -> Assessment:
        if hasattr(self.judge, "assess_async"):
            assessment = await self.judge.assess_async(probe, response)
        else:
            assessment = self.judge.assess(probe, response)
        self.by_verdict[assessment.verdict] += 1
        self.by_technique[probe.technique][assessment.verdict] += 1
        return assessment

    def make_agent(self, sandbox=None):
        from ..agentlab import SandboxAgent

        acfg = self.config.get("agent", {})
        return SandboxAgent(
            target=self.target,
            sandbox=sandbox,
            allowed_tools=set(acfg.get("allowed_tools", [])),
            max_steps=int(acfg.get("max_steps", 6)),
        )

    def option(self, attack_id: str, key: str, default: Any) -> Any:
        return self.config.get("attacks", {}).get(attack_id, {}).get(key, default)


class Attack(abc.ABC):
    """One attack family.

    Subclasses implement :meth:`probes` (the corpus) and may override
    :meth:`execute` for search-based or agentic flows.
    """

    attack_id: str = "attack"
    technique: str = "Technique"
    title: str = "Attack"
    description: str = ""
    severity: Severity = Severity.HIGH
    options: dict[str, Any] = {}

    def __init__(self, options: dict[str, Any] | None = None):
        self.options = dict(options or {})

    # -- corpus -------------------------------------------------------------

    @abc.abstractmethod
    def probes(self, ctx: RunContext) -> Iterable[Probe]:
        """Yield the adversarial probes for this family."""

    def probe(
        self,
        payload: str,
        success_patterns: list[str],
        severity: Severity | None = None,
        metadata: dict[str, Any] | None = None,
        messages: list[dict[str, str]] | None = None,
        attachments=None,
    ) -> Probe:
        meta: dict[str, Any] = {
            "success_patterns": success_patterns,
            "severity": str(severity or self.severity),
        }
        if metadata:
            meta.update(metadata)
        return Probe(
            payload=payload,
            attack=self.attack_id,
            technique=self.technique,
            messages=messages,
            attachments=list(attachments or []),
            metadata=meta,
        )

    # -- default execution loop --------------------------------------------

    async def execute(self, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for probe in self.probes(ctx):
            response, err = await ctx.send(probe)
            if err:
                continue
            assessment = await ctx.assess_async(probe, response)
            if assessment.verdict != "vulnerable":
                continue
            if probe.fingerprint in seen:
                continue
            seen.add(probe.fingerprint)
            findings.append(
                Finding(
                    attack=self.attack_id,
                    technique=self.technique,
                    severity=assessment.severity,
                    score=assessment.score,
                    payload=probe.payload,
                    response=response[:4000],
                    evidence=assessment.evidence,
                    metadata={
                        "attachments": [a.name for a in probe.attachments],
                        **{k: v for k, v in probe.metadata.items() if k not in ("success_patterns",)},
                    },
                )
            )
        log.info("%s: %d finding(s)", self.attack_id, len(findings))
        return findings


def merge_findings(*groups: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for group in groups:
        for f in group:
            if f.fingerprint in seen:
                continue
            seen.add(f.fingerprint)
            out.append(f)
    return out
