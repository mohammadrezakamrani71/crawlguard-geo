"""Web server access log analyzer for Search Bots, AI Crawlers, bandwidth consumption, and crawl-budget waste."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field


COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"[^"]*"\s+"(?P<ua>[^"]*)"'
)

BOT_SIGNATURES: list[tuple[str, str, str]] = [
    # (pattern_lower, bot_name, bot_group)
    ("googlebot", "Googlebot", "SEARCH_ENGINE"),
    ("bingbot", "Bingbot", "SEARCH_ENGINE"),
    ("duckduckbot", "DuckDuckBot", "SEARCH_ENGINE"),
    ("yandexbot", "YandexBot", "SEARCH_ENGINE"),
    ("gptbot", "GPTBot", "AI_CRAWLER"),
    ("oai-searchbot", "OAI-SearchBot", "AI_CRAWLER"),
    ("claudebot", "ClaudeBot", "AI_CRAWLER"),
    ("anthropic-ai", "Anthropic-AI", "AI_CRAWLER"),
    ("perplexitybot", "PerplexityBot", "AI_CRAWLER"),
    ("google-extended", "Google-Extended", "AI_CRAWLER"),
    ("bytespider", "Bytespider", "AI_CRAWLER"),
    ("ccbot", "CCBot", "AI_CRAWLER"),
    ("meta-externalagent", "Meta-ExternalAgent", "AI_CRAWLER"),
]


@dataclass
class BotMetrics:
    name: str
    group: str  # "SEARCH_ENGINE" | "AI_CRAWLER" | "OTHER_BOT"
    requests: int
    bytes_transferred: int
    ok_2xx: int
    redirect_3xx: int
    error_4xx: int
    error_5xx: int
    waste_pct: float
    unique_ips: int


@dataclass
class LogAuditResult:
    total_requests: int
    total_bot_requests: int
    total_bot_bytes: int
    crawl_waste_pct: float
    bots: list[BotMetrics] = field(default_factory=list)
    top_wasted_paths: list[tuple[str, int]] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)


def _classify_ua(ua: str) -> tuple[str, str] | None:
    low = ua.lower()
    for token, name, group in BOT_SIGNATURES:
        if token in low:
            return name, group
    if any(k in low for k in ("bot", "crawler", "spider", "scraper")):
        return "Generic-Bot", "OTHER_BOT"
    return None


def analyze_access_log(log_text: str) -> LogAuditResult:
    """Parse Nginx/Apache combined access logs and quantify Search & AI bot traffic."""
    total_requests = 0
    total_bot_requests = 0
    total_bot_bytes = 0
    total_bot_waste = 0

    bot_stats: dict[str, dict] = {}
    wasted_paths: Counter[str] = Counter()

    for raw in log_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = COMBINED_LOG_RE.match(line)
        if not m:
            continue
        total_requests += 1

        ua = m.group("ua")
        bot_info = _classify_ua(ua)
        if not bot_info:
            continue

        bot_name, bot_group = bot_info
        status = int(m.group("status"))
        size = 0 if m.group("bytes") == "-" else int(m.group("bytes"))
        ip = m.group("ip")
        path = m.group("path")

        total_bot_requests += 1
        total_bot_bytes += size

        entry = bot_stats.setdefault(
            bot_name,
            {
                "group": bot_group,
                "requests": 0,
                "bytes": 0,
                "2xx": 0,
                "3xx": 0,
                "4xx": 0,
                "5xx": 0,
                "ips": set(),
            },
        )
        entry["requests"] += 1
        entry["bytes"] += size
        entry["ips"].add(ip)

        if 200 <= status < 300:
            entry["2xx"] += 1
        elif 300 <= status < 400:
            entry["3xx"] += 1
        elif 400 <= status < 500:
            entry["4xx"] += 1
            total_bot_waste += 1
            wasted_paths[f"{status} {path}"] += 1
        elif status >= 500:
            entry["5xx"] += 1
            total_bot_waste += 1
            wasted_paths[f"{status} {path}"] += 1

    bots: list[BotMetrics] = []
    alerts: list[str] = []

    for name, s in sorted(bot_stats.items(), key=lambda kv: kv[1]["requests"], reverse=True):
        reqs = s["requests"]
        waste = round(((s["4xx"] + s["5xx"]) / reqs) * 100.0, 1) if reqs else 0.0
        bm = BotMetrics(
            name=name,
            group=s["group"],
            requests=reqs,
            bytes_transferred=s["bytes"],
            ok_2xx=s["2xx"],
            redirect_3xx=s["3xx"],
            error_4xx=s["4xx"],
            error_5xx=s["5xx"],
            waste_pct=waste,
            unique_ips=len(s["ips"]),
        )
        bots.append(bm)
        if bm.error_5xx > 0:
            alerts.append(f"CRITICAL: {bm.name} hit {bm.error_5xx} HTTP 5xx server error(s) — hurts search/AI indexing.")
        elif bm.waste_pct >= 30.0 and bm.requests >= 3:
            alerts.append(f"WARN: {bm.name} wasted {bm.waste_pct}% of crawl requests on 4xx/5xx responses.")

    overall_waste = round((total_bot_waste / total_bot_requests) * 100.0, 1) if total_bot_requests else 0.0

    return LogAuditResult(
        total_requests=total_requests,
        total_bot_requests=total_bot_requests,
        total_bot_bytes=total_bot_bytes,
        crawl_waste_pct=overall_waste,
        bots=bots,
        top_wasted_paths=wasted_paths.most_common(5),
        alerts=alerts,
    )
