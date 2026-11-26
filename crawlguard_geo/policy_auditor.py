"""Audits robots.txt and llms.txt policies for Search SEO and AI/GEO readiness."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class PolicyFinding:
    rule_id: str
    scope: str     # "ROBOTS" | "LLMS"
    title: str
    status: str    # "PASS" | "WARN" | "FAIL"
    detail: str
    recommendation: str


AI_BOTS = ("GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "Bytespider", "CCBot")


def audit_robots_txt(robots_text: str) -> list[PolicyFinding]:
    """Audit robots.txt for sitemap declaration, accidental full-site blocks, and AI bot governance."""
    findings: list[PolicyFinding] = []
    lines = [l.strip() for l in robots_text.splitlines() if l.strip() and not l.strip().startswith("#")]
    joined = "\n".join(lines)

    # 1. Sitemap declaration
    if re.search(r"(?i)^Sitemap:\s*https?://", joined, re.MULTILINE):
        findings.append(
            PolicyFinding("GEO-001", "ROBOTS", "Sitemap Declaration", "PASS", "XML Sitemap URL declared in robots.txt.", "No action required.")
        )
    else:
        findings.append(
            PolicyFinding("GEO-001", "ROBOTS", "Sitemap Declaration", "WARN", "No `Sitemap:` directive found.", "Add `Sitemap: https://yourdomain.com/sitemap.xml` to guide crawlers.")
        )

    # 2. Accidental global Disallow: /
    blocks = re.split(r"(?i)(?=^User-agent:)", joined, flags=re.MULTILINE)
    global_disallow = False
    for blk in blocks:
        if re.search(r"(?i)^User-agent:\s*\*\s*$", blk, re.MULTILINE) and re.search(
            r"(?i)^Disallow:\s*/\s*$", blk, re.MULTILINE
        ):
            global_disallow = True
            break

    if global_disallow:
        findings.append(
            PolicyFinding("GEO-002", "ROBOTS", "Global Crawl Trap Check", "FAIL", "`User-agent: *` has `Disallow: /`, blocking all search engines.", "Restrict `Disallow:` only to private/admin paths unless site is intentionally private.")
        )
    else:
        findings.append(
            PolicyFinding("GEO-002", "ROBOTS", "Global Crawl Trap Check", "PASS", "No accidental global `Disallow: /` rule detected.", "No action required.")
        )

    # 3. Explicit AI crawler governance
    mentioned_ai = [b for b in AI_BOTS if re.search(rf"(?i)^User-agent:\s*{re.escape(b)}\b", joined, re.MULTILINE)]
    if mentioned_ai:
        findings.append(
            PolicyFinding(
                "GEO-003",
                "ROBOTS",
                "AI Crawler Policy Governance",
                "PASS",
                f"Explicit rules defined for AI crawlers: {', '.join(mentioned_ai)}.",
                "Review quarterly as new AI user-agents emerge.",
            )
        )
    else:
        findings.append(
            PolicyFinding(
                "GEO-003",
                "ROBOTS",
                "AI Crawler Policy Governance",
                "WARN",
                "No explicit rules for major AI crawlers (GPTBot, ClaudeBot, PerplexityBot, Bytespider).",
                "Explicitly allow high-value AI answer engines and disallow aggressive scrapers to protect bandwidth.",
            )
        )

    return findings


def audit_llms_txt(llms_text: str | None) -> list[PolicyFinding]:
    """Audit llms.txt presence and Markdown structure for Generative Engine Optimization (GEO)."""
    if not llms_text or not llms_text.strip():
        return [
            PolicyFinding(
                "GEO-004",
                "LLMS",
                "llms.txt Readiness",
                "WARN",
                "No `llms.txt` file provided or file is empty.",
                "Publish `/llms.txt` in Markdown format with an H1 title, summary blockquote, and key documentation links for AI agents.",
            )
        ]

    findings: list[PolicyFinding] = []
    has_h1 = bool(re.search(r"^#\s+\S+", llms_text, re.MULTILINE))
    links = re.findall(r"\[[^\]]+\]\(https?://[^)]+\)", llms_text)

    if has_h1 and len(links) >= 2:
        findings.append(
            PolicyFinding(
                "GEO-004",
                "LLMS",
                "llms.txt Structure & Links",
                "PASS",
                f"Valid Markdown H1 header and {len(links)} curated resource link(s) found.",
                "No action required.",
            )
        )
    else:
        findings.append(
            PolicyFinding(
                "GEO-004",
                "LLMS",
                "llms.txt Structure & Links",
                "WARN",
                f"H1 present: {has_h1} | Markdown links found: {len(links)}.",
                "Include an `# Organization/Site` H1 header and curated `[Title](https://...)` links to canonical docs.",
            )
        )

    return findings
