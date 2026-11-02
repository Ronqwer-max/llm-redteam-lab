import json

from redteam.core.config import load_config
from redteam.core.finding import Severity
from redteam.core.report import render_html, render_markdown, to_json, write_report
from redteam.core.runner import run_campaign_sync


def test_full_campaign_finds_all_five_techniques(tmp_path):
    cfg = load_config(None)
    cfg["run"]["name"] = "e2e"
    result = run_campaign_sync(cfg)

    techniques = {f.technique for f in result.findings}
    assert any("prompt injection" in t for t in techniques)
    assert any("Jailbreaking" in t for t in techniques)
    assert any("privilege escalation" in t for t in techniques)
    assert any("memory" in t.lower() or "Training data" in t for t in techniques)
    assert any("Multimodal" in t for t in techniques)

    assert result.max_severity >= Severity.CRITICAL
    assert result.stats["probes_sent"] > 0
    # negative controls must never produce findings
    for f in result.findings:
        assert "SHOULD_NEVER_HAPPEN" not in f.response
        assert not f.payload.startswith("Read my notes file and list")


def test_campaign_budget_and_determinism():
    cfg = load_config(None)
    cfg["attacks"]["jailbreak"] = {"generations": 3, "population": 6, "budget": 12}
    first = run_campaign_sync(cfg)
    second = run_campaign_sync(cfg)
    assert [f.payload for f in first.findings] == [f.payload for f in second.findings]


def test_hardened_config_produces_zero_findings():
    cfg = load_config(None)
    cfg["target"]["vulnerable"] = {
        "system_prompt": False,
        "policy": False,
        "memory": False,
        "attachment_ocr": False,
        "prefix": False,
        "say": False,
        "tool_directives": False,
    }
    # jailbreak search and memory/direct attacks still run, but find nothing
    result = run_campaign_sync(cfg)
    assert result.findings == [], [f.payload for f in result.findings]
    assert result.max_severity == Severity.INFO


def test_report_artifacts(tmp_path):
    cfg = load_config(None)
    cfg["run"]["name"] = "report-test"
    result = run_campaign_sync(cfg)

    out = write_report(result, tmp_path)
    json_data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert json_data["summary"]["total_findings"] == len(result.findings)
    assert json_data["run"]["name"] == "report-test"

    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Technique coverage" in html and "Findings" in html
    md = (out / "report.md").read_text(encoding="utf-8")
    assert md.startswith("# RedTeam report")

    # direct renderers also work
    assert "<!doctype html>" in render_html(result)
    assert json.dumps(to_json(result))
    assert "authorized to assess" in render_markdown(result)
