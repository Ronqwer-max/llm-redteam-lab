"""Command-line interface.

    redteam list                       # show registered attack families
    redteam run -c configs/default.toml
    redteam run --offline              # pure defaults, mock target
    redteam run -c cfg.toml --fail-on critical   # CI gate
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from . import __version__
from .core import registry
from .core.config import load_config
from .core.finding import Severity
from .core.report import write_report
from .core.runner import run_campaign


def _cmd_list(_args: argparse.Namespace) -> int:
    from . import attacks as _attacks  # noqa: F401 - triggers registration

    print("Registered attack families:\n")
    for attack_id in registry.available():
        cls = registry.get(attack_id)
        print(f"  {attack_id:22} {cls.technique}")
        print(f"  {'':22} {cls.description.strip()[:96]}")
        print()
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    cfg = load_config(args.config)
    if args.seed is not None:
        cfg["run"]["seed"] = args.seed
    if args.name:
        cfg["run"]["name"] = args.name
    if args.attacks:
        cfg["attacks"]["enabled"] = [a.strip() for a in args.attacks.split(",") if a.strip()]
    if args.target:
        cfg["target"]["type"] = args.target

    result = asyncio.run(run_campaign(cfg, config_path=args.config))

    out_dir = Path(args.out or cfg.get("report", {}).get("output_dir", "reports"))
    report_path = write_report(result, out_dir)

    # ---- console summary ----
    counts = result.counts_by_severity()
    print()
    print(f"Campaign '{result.run_name}' finished in {result.duration_s}s "
          f"(target={result.target}, probes={result.stats.get('probes_sent', 0)})")
    print(
        "  findings: "
        + ", ".join(f"{k}={v}" for k, v in counts.items() if v or k in ("CRITICAL", "HIGH"))
    )
    for technique, verdicts in sorted(result.stats.get("by_technique", {}).items()):
        print(f"    - {technique}: " + ", ".join(f"{k}={v}" for k, v in sorted(verdicts.items())))
    if result.stats.get("attack_errors"):
        for err in result.stats["attack_errors"]:
            print(f"  ! {err}", file=sys.stderr)
    print(f"\n  report: {report_path / 'report.html'}")

    fail_on = args.fail_on or cfg.get("report", {}).get("fail_on", "high")
    if fail_on and fail_on.lower() != "none":
        threshold = Severity.from_str(fail_on)
        if result.max_severity >= threshold:
            print(f"\nFAIL: findings at or above severity {threshold} "
                  f"(max={result.max_severity})")
            return 1
    print(f"\nPASS: max severity {result.max_severity}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redteam",
        description="Adversarial robustness testing for LLM applications. "
                    "Only test systems you own or are authorized to assess.",
    )
    parser.add_argument("--version", action="version", version=f"llm-redteam-lab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list registered attack families")
    p_list.set_defaults(func=_cmd_list)

    p_run = sub.add_parser("run", help="run a red-team campaign")
    p_run.add_argument("-c", "--config", help="TOML config file", default=None)
    p_run.add_argument("--offline", action="store_true",
                       help="ignore config and run pure defaults (mock target)")
    p_run.add_argument("-o", "--out", help="report output directory (default: reports/)")
    p_run.add_argument("--name", help="override run name")
    p_run.add_argument("--seed", type=int, help="override RNG seed")
    p_run.add_argument("--attacks", help="comma-separated attack ids to run")
    p_run.add_argument("--target", choices=["mock", "openai"], help="override target type")
    p_run.add_argument("--fail-on", dest="fail_on",
                       help="exit non-zero if findings reach this severity "
                            "(critical|high|medium|low|info|none)")
    p_run.add_argument("-v", "--verbose", action="store_true")
    p_run.set_defaults(func=_cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "offline", False):
        args.config = None
    if args.command == "run" and args.config is None and not args.offline:
        # default to the bundled config when present
        default_cfg = Path("configs/default.toml")
        args.config = str(default_cfg) if default_cfg.exists() else None
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
