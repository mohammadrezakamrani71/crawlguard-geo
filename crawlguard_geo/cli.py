"""Command-line interface for CrawlGuard-GEO."""

from __future__ import annotations

import argparse
from pathlib import Path

from .log_analyzer import LogAuditResult, analyze_access_log
from .policy_auditor import PolicyFinding, audit_llms_txt, audit_robots_txt
from .reporter import render_html_report, render_json_report, render_markdown_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="crawlguard-geo",
        description="AI Crawler, Search Bot & robots.txt/llms.txt Network-Edge Auditor",
    )
    parser.add_argument("--access-log", type=Path, help="Path to Nginx/Apache combined access log")
    parser.add_argument("--robots", type=Path, help="Path to robots.txt file")
    parser.add_argument("--llms", type=Path, help="Path to llms.txt file")
    parser.add_argument("--out-md", type=Path, help="Optional Markdown report output path")
    parser.add_argument("--out-html", type=Path, help="Optional HTML report output path")
    parser.add_argument("--out-json", type=Path, help="Optional JSON report output path")
    args = parser.parse_args(argv)

    if not any((args.access_log, args.robots, args.llms)):
        parser.error("Provide at least one of --access-log, --robots, or --llms.")

    log_res: LogAuditResult | None = None
    policies: list[PolicyFinding] = []

    if args.access_log:
        log_res = analyze_access_log(args.access_log.read_text(encoding="utf-8"))
    if args.robots:
        policies.extend(audit_robots_txt(args.robots.read_text(encoding="utf-8")))
    if args.llms:
        policies.extend(audit_llms_txt(args.llms.read_text(encoding="utf-8")))

    md = render_markdown_report(log_res, policies)
    print(md)

    if args.out_md:
        args.out_md.write_text(md, encoding="utf-8")
    if args.out_html:
        args.out_html.write_text(render_html_report(log_res, policies), encoding="utf-8")
    if args.out_json:
        args.out_json.write_text(render_json_report(log_res, policies), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
