"""Campaign orchestration: build target/judge/attacks, run concurrently,
collect and de-duplicate findings."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from .. import attacks as _attacks_pkg  # noqa: F401  (imports register every attack)
from ..core import registry
from ..core.finding import Finding, Severity
from ..core.judge import build_judge
from ..attacks.base import Attack, RunContext
from ..targets import build_target

log = logging.getLogger("redteam")


@dataclass
class CampaignResult:
    run_name: str
    started_at: float
    duration_s: float
    findings: list[Finding]
    stats: dict[str, Any]
    target: str
    config_path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts


def build_attacks(cfg: dict[str, Any]) -> list[Attack]:
    enabled = cfg.get("attacks", {}).get("enabled") or registry.available()
    shared = cfg.get("attacks", {})
    out: list[Attack] = []
    for attack_id in enabled:
        cls = registry.get(attack_id)
        options = shared.get(attack_id, {})
        out.append(cls(options=options))
    return out


async def run_campaign(cfg: dict[str, Any], config_path: str | None = None) -> CampaignResult:
    started = time.time()
    target = build_target(cfg)
    judge = build_judge(cfg, target)
    ctx = RunContext(
        target=target,
        judge=judge,
        config=cfg,
        concurrency=int(cfg.get("run", {}).get("concurrency", 4)),
    )
    attack_objs = build_attacks(cfg)
    log.info(
        "campaign %r: target=%s attacks=%s",
        cfg.get("run", {}).get("name", "campaign"),
        target.name,
        [a.attack_id for a in attack_objs],
    )

    results = await asyncio.gather(
        *(a.execute(ctx) for a in attack_objs), return_exceptions=True
    )

    findings: list[Finding] = []
    errors: list[str] = []
    for attack, result in zip(attack_objs, results):
        if isinstance(result, BaseException):
            errors.append(f"{attack.attack_id}: {result}")
            log.error("attack %s crashed: %s", attack.attack_id, result)
            continue
        findings.extend(result)

    # global de-dup
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f.fingerprint, f)
    final = sorted(
        unique.values(), key=lambda f: (-int(f.severity), -f.score, f.attack)
    )

    await target.close()
    duration = time.time() - started

    stats = {
        "probes_sent": ctx.stats_probes + 0,
        "target_calls": getattr(target, "calls", None),
        "errors": ctx.errors + len(errors),
        "attack_errors": errors,
        "by_verdict": dict(ctx.by_verdict),
        "by_technique": {k: dict(v) for k, v in ctx.by_technique.items()},
        "findings": len(final),
        "by_severity": _counts(final),
    }
    return CampaignResult(
        run_name=cfg.get("run", {}).get("name", "campaign"),
        started_at=started,
        duration_s=round(duration, 3),
        findings=final,
        stats=stats,
        target=target.name,
        config_path=config_path,
        meta={"attacks_run": [a.attack_id for a in attack_objs], "seed": cfg.get("run", {}).get("seed")},
    )


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.name: 0 for s in Severity}
    for f in findings:
        counts[f.severity.name] += 1
    return counts


def run_campaign_sync(cfg: dict[str, Any], config_path: str | None = None) -> CampaignResult:
    return asyncio.run(run_campaign(cfg, config_path))
