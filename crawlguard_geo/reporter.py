"""Markdown, JSON, and dark-theme HTML report generator for CrawlGuard-GEO."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from datetime import datetime, timezone

from .log_analyzer import LogAuditResult
from .policy_auditor import PolicyFinding


def _fmt_kb(num_bytes: int) -> str:
    return f"{num_bytes / 1024:.1f} KB"


def render_json_report(log_res: LogAuditResult | None, policies: list[PolicyFinding]) -> str:
    payload = {
        "log_audit": asdict(log_res) if log_res else None,
        "policy_findings": [asdict(p) for p in policies],
    }
    return json.dumps(payload, indent=2)


def render_markdown_report(log_res: LogAuditResult | None, policies: list[PolicyFinding]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# CrawlGuard-GEO — AI Crawler, Search Bot & Policy Audit Report",
        "",
        f"**Generated:** {timestamp}",
        "",
    ]

    if log_res:
        lines.extend(
            [
                "## 1. Bot Traffic & Crawl-Budget Summary",
                "",
                f"- **Total Requests Parsed:** {log_res.total_requests}",
                f"- **Bot Requests:** {log_res.total_bot_requests} ({_fmt_kb(log_res.total_bot_bytes)} bandwidth)",
                f"- **Crawl-Budget Waste (4xx/5xx):** {log_res.crawl_waste_pct}%",
                "",
                "| Bot | Category | Requests | Bandwidth | 2xx | 4xx | 5xx | Waste % | Unique IPs |",
                "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for b in log_res.bots:
            lines.append(
                f"| **{b.name}** | {b.group} | {b.requests} | {_fmt_kb(b.bytes_transferred)} | "
                f"{b.ok_2xx} | {b.error_4xx} | {b.error_5xx} | {b.waste_pct:.1f}% | {b.unique_ips} |"
            )
        lines.append("")
        if log_res.alerts:
            lines.append("### Edge Alerts")
            for a in log_res.alerts:
                lines.append(f"- {a}")
            lines.append("")

    if policies:
        lines.extend(
            [
                "## 2. robots.txt & llms.txt Policy Audit",
                "",
                "| Rule | Scope | Control | Status | Detail | Recommendation |",
                "| :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for p in policies:
            lines.append(
                f"| `{p.rule_id}` | {p.scope} | {p.title} | **{p.status}** | {p.detail} | {p.recommendation} |"
            )
        lines.append("")

    return "\n".join(lines)


def render_html_report(log_res: LogAuditResult | None, policies: list[PolicyFinding]) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def badge(status: str) -> str:
        colors = {"PASS": "#16a34a", "WARN": "#d97706", "FAIL": "#dc2626"}
        bg = colors.get(status, "#475569")
        return f'<span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">{html.escape(status)}</span>'

    bot_rows = ""
    if log_res:
        bot_rows = "\n".join(
            f"<tr><td><strong>{html.escape(b.name)}</strong></td><td>{html.escape(b.group)}</td>"
            f"<td>{b.requests}</td><td>{_fmt_kb(b.bytes_transferred)}</td>"
            f"<td>{b.ok_2xx}</td><td>{b.error_4xx}</td><td>{b.error_5xx}</td>"
            f"<td>{b.waste_pct:.1f}%</td><td>{b.unique_ips}</td></tr>"
            for b in log_res.bots
        )

    pol_rows = "\n".join(
        f"<tr><td><code>{html.escape(p.rule_id)}</code></td><td>{html.escape(p.scope)}</td>"
        f"<td>{html.escape(p.title)}</td><td>{badge(p.status)}</td>"
        f"<td>{html.escape(p.detail)}</td><td>{html.escape(p.recommendation)}</td></tr>"
        for p in policies
    )

    bot_reqs = log_res.total_bot_requests if log_res else 0
    bot_bw = _fmt_kb(log_res.total_bot_bytes) if log_res else "0 KB"
    waste = f"{log_res.crawl_waste_pct:.1f}%" if log_res else "0.0%"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CrawlGuard-GEO Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 32px; background: #0f172a; color: #e2e8f0; }}
  .container {{ max-width: 1140px; margin: 0 auto; background: #1e293b; padding: 28px; border-radius: 12px; }}
  h1 {{ margin-top: 0; font-size: 24px; color: #f8fafc; }}
  .meta {{ color: #94a3b8; font-size: 14px; margin-bottom: 20px; }}
  .kpis {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }}
  .kpi {{ background: #0f172a; padding: 14px 16px; border-radius: 8px; border: 1px solid #334155; }}
  .kpi span {{ font-size: 12px; color: #94a3b8; display: block; }}
  .kpi strong {{ font-size: 22px; color: #38bdf8; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 26px; font-size: 14px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #334155; }}
  th {{ background: #0f172a; color: #cbd5e1; }}
  code {{ background: #0f172a; color: #7dd3fc; padding: 2px 5px; border-radius: 4px; }}
</style>
</head>
<body>
<div class="container">
  <h1>CrawlGuard-GEO — AI Crawler &amp; Search Bot Audit</h1>
  <div class="meta">Generated: {html.escape(timestamp)}</div>
  <div class="kpis">
    <div class="kpi"><span>Bot Requests</span><strong>{bot_reqs}</strong></div>
    <div class="kpi"><span>Bot Bandwidth</span><strong>{bot_bw}</strong></div>
    <div class="kpi"><span>Crawl Waste (4xx/5xx)</span><strong>{waste}</strong></div>
    <div class="kpi"><span>Policy Checks</span><strong>{len(policies)}</strong></div>
  </div>
  <h2>Bot Traffic &amp; Crawl-Budget Breakdown</h2>
  <table>
    <thead><tr><th>Bot</th><th>Category</th><th>Requests</th><th>Bandwidth</th><th>2xx</th><th>4xx</th><th>5xx</th><th>Waste %</th><th>IPs</th></tr></thead>
    <tbody>{bot_rows or '<tr><td colspan="9">No access log analyzed.</td></tr>'}</tbody>
  </table>
  <h2>robots.txt &amp; llms.txt Governance</h2>
  <table>
    <thead><tr><th>Rule</th><th>Scope</th><th>Control</th><th>Status</th><th>Detail</th><th>Recommendation</th></tr></thead>
    <tbody>{pol_rows or '<tr><td colspan="6">No policy files analyzed.</td></tr>'}</tbody>
  </table>
</div>
</body>
</html>
"""
