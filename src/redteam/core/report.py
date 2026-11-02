"""Report rendering: machine-readable JSON + a self-contained HTML page."""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from .finding import Finding, Severity
from .runner import CampaignResult

_SEV_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#b45309",
    "MEDIUM": "#a16207",
    "LOW": "#1d4ed8",
    "INFO": "#4b5563",
}


def to_json(result: CampaignResult) -> dict[str, Any]:
    return {
        "run": {
            "name": result.run_name,
            "target": result.target,
            "config": result.config_path,
            "started_at": result.started_at,
            "generated_at": time.time(),
            "duration_s": result.duration_s,
            **result.meta,
        },
        "stats": result.stats,
        "findings": [f.to_dict() for f in result.findings],
        "summary": {
            "total_findings": len(result.findings),
            "max_severity": str(result.max_severity),
            "by_severity": result.counts_by_severity(),
        },
    }


def _tech_rows(result: CampaignResult) -> str:
    rows = []
    by_tech: dict[str, dict[str, int]] = {}
    for f in result.findings:
        bucket = by_tech.setdefault(f.technique, {})
        bucket[str(f.severity)] = bucket.get(str(f.severity), 0) + 1
    techniques = sorted(
        set(list(by_tech) + [t for t in result.stats.get("by_technique", {})])
    )
    verdicts = result.stats.get("by_verdict", {})
    for tech in techniques:
        probes = sum(
            v.get("probes", 0) for k, v in result.stats.get("by_technique", {}).items() if k == tech
        )
        vuln = sum(
            v.get("vulnerable", 0) for k, v in result.stats.get("by_technique", {}).items() if k == tech
        )
        chips = "".join(
            f'<span class="chip" style="background:{_SEV_COLORS.get(sev, "#333")}">{sev} x{n}</span>'
            for sev, n in sorted(by_tech.get(tech, {}).items())
        ) or '<span class="chip ok">clean</span>'
        rows.append(
            f"<tr><td>{html.escape(str(tech))}</td>"
            f"<td>{probes or '-'}</td><td>{vuln if vuln else 0}</td><td>{chips}</td></tr>"
        )
    return "\n".join(rows) or "<tr><td colspan=4>No techniques ran.</td></tr>"


def render_html(result: CampaignResult) -> str:
    findings_html: list[str] = []
    for i, f in enumerate(result.findings, 1):
        sev = str(f.severity)
        evidence = "".join(f"<li>{html.escape(e)}</li>" for e in f.evidence)
        attachments = f.metadata.get("attachments") or []
        att_html = (
            f'<p class="meta">attachments: {html.escape(", ".join(map(str, attachments)))}</p>'
            if attachments
            else ""
        )
        variant = f.metadata.get("variant")
        findings_html.append(
            f"""
      <details class="finding" open>
        <summary>
          <span class="sev" style="background:{_SEV_COLORS.get(sev, '#333')}">{sev}</span>
          <strong>#{i} {html.escape(f.technique)}</strong>
          <span class="dim">({html.escape(f.attack)} · score {f.score:.2f} · {html.escape(str(variant or ''))})</span>
        </summary>
        <p class="meta">payload fingerprint <code>{f.fingerprint}</code> · id <code>{f.id}</code></p>
        <pre class="payload">{html.escape(f.payload or '(multi-turn conversation)')}</pre>
        <h4>Target response</h4>
        <pre class="response">{html.escape(f.response)}</pre>
        <h4>Evidence</h4>
        <ul>{evidence}</ul>
        {att_html}
      </details>"""
        )

    counts = result.counts_by_severity()
    count_chips = "".join(
        f'<div class="stat"><div class="num" style="color:{_SEV_COLORS[s]}">{counts[s]}</div>'
        f'<div class="lbl">{s}</div></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>RedTeam report — {html.escape(result.run_name)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font: 15px/1.55 ui-sans-serif, system-ui, sans-serif; margin: 0;
         background: #0b0f17; color: #e5e7eb; }}
  header {{ padding: 32px 40px 18px; border-bottom: 1px solid #1f2937; }}
  h1 {{ margin: 0 0 6px; font-size: 26px; }}
  .dim {{ color: #9ca3af; font-size: 13px; }}
  main {{ padding: 24px 40px 64px; max-width: 1100px; }}
  .stats {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 18px 0 8px; }}
  .stat {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px;
           padding: 12px 20px; text-align: center; min-width: 96px; }}
  .stat .num {{ font-size: 28px; font-weight: 700; }}
  .stat .lbl {{ font-size: 11px; letter-spacing: .08em; color: #9ca3af; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 18px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #1f2937;
            vertical-align: top; font-size: 14px; }}
  th {{ color: #9ca3af; font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }}
  .chip {{ display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px;
           margin-right: 6px; color: #fff; font-weight: 600; }}
  .chip.ok {{ background: #065f46; }}
  .sev {{ display: inline-block; padding: 2px 10px; border-radius: 6px; font-size: 11px;
          font-weight: 700; color: #fff; margin-right: 8px; }}
  details.finding {{ background: #111827; border: 1px solid #1f2937; border-radius: 10px;
                     padding: 12px 16px; margin: 12px 0; }}
  details summary {{ cursor: pointer; }}
  pre {{ background: #0b0f17; border: 1px solid #1f2937; border-radius: 8px; padding: 12px;
        white-space: pre-wrap; word-break: break-word; font-size: 13px; }}
  .payload {{ border-left: 3px solid #6366f1; }}
  .response {{ border-left: 3px solid #f59e0b; }}
  h4 {{ margin: 16px 0 6px; font-size: 13px; color: #9ca3af;
        text-transform: uppercase; letter-spacing: .06em; }}
  .meta {{ font-size: 12px; color: #9ca3af; }}
  code {{ background: #1f2937; padding: 1px 6px; border-radius: 4px; }}
  footer {{ padding: 18px 40px; border-top: 1px solid #1f2937; font-size: 12px; color: #6b7280; }}
</style></head>
<body>
<header>
  <h1>RedTeam campaign — {html.escape(result.run_name)}</h1>
  <div class="dim">target <code>{html.escape(result.target)}</code> ·
    attacks {html.escape(", ".join(result.meta.get("attacks_run", [])))} ·
    {result.stats.get("probes_sent", 0)} probes · {result.duration_s}s ·
    generated {time.strftime("%Y-%m-%d %H:%M:%S")}</div>
  <div class="stats">{count_chips}
    <div class="stat"><div class="num">{result.stats.get("probes_sent", 0)}</div><div class="lbl">PROBES</div></div>
    <div class="stat"><div class="num">{result.stats.get("errors", 0)}</div><div class="lbl">ERRORS</div></div>
  </div>
</header>
<main>
  <h2>Technique coverage</h2>
  <table>
    <tr><th>Technique</th><th>Probes</th><th>Vulnerable</th><th>Findings</th></tr>
    {_tech_rows(result)}
  </table>
  <h2>Findings ({len(result.findings)})</h2>
  {''.join(findings_html) or '<p class="dim">No findings — the target withstood this campaign.</p>'}
</main>
<footer>Generated by llm-redteam-lab · only test systems you own or are authorized to assess.</footer>
</body></html>"""


def write_report(result: CampaignResult, output_dir: str | Path) -> Path:
    out = Path(output_dir) / f"{result.run_name}-{time.strftime('%Y%m%d-%H%M%S')}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(to_json(result), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "report.html").write_text(render_html(result), encoding="utf-8")
    (out / "report.md").write_text(render_markdown(result), encoding="utf-8")
    latest = Path(output_dir) / "latest"
    try:
        if latest.is_symlink() or latest.exists():
            if latest.is_dir() and not latest.is_symlink():
                import shutil

                shutil.rmtree(latest)
            else:
                latest.unlink()
        latest.symlink_to(out.name, target_is_directory=True)
    except OSError:
        # Windows without symlink permission: write a pointer file instead.
        latest.write_text(str(out.resolve()), encoding="utf-8")
    return out


def render_markdown(result: CampaignResult) -> str:
    counts = result.counts_by_severity()
    lines = [
        f"# RedTeam report — {result.run_name}",
        "",
        f"- **Target:** `{result.target}`",
        f"- **Attacks:** {', '.join(result.meta.get('attacks_run', []))}",
        f"- **Probes sent:** {result.stats.get('probes_sent', 0)}",
        f"- **Findings:** {len(result.findings)} "
        f"(CRITICAL {counts['CRITICAL']} / HIGH {counts['HIGH']} / MEDIUM {counts['MEDIUM']})",
        "",
        "| # | Severity | Technique | Variant | Evidence |",
        "|---|----------|-----------|---------|----------|",
    ]
    for i, f in enumerate(result.findings, 1):
        ev = "; ".join(f.evidence[:2])[:140]
        lines.append(
            f"| {i} | **{f.severity}** | {f.technique} | "
            f"{f.metadata.get('variant', '-')} | {ev.replace('|', '/')} |"
        )
    lines += [
        "",
        "> Only test systems you own or are explicitly authorized to assess.",
        "",
    ]
    return "\n".join(lines)
