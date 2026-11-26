# CrawlGuard-GEO — AI Crawler, Search Bot & `robots.txt`/`llms.txt` Network-Edge Auditor

**CrawlGuard-GEO** is a zero-dependency Python 3.10+ CLI tool built for the **AI Search (GEO) & Network Edge Security** era. It analyzes Nginx/Apache server logs alongside `robots.txt` and `llms.txt` policies to quantify **AI crawler bandwidth**, detect **crawl-budget waste (4xx/5xx)**, flag **indexing-breaking 5xx errors**, and audit **Generative Engine Optimization (GEO)** readiness.

## Why CrawlGuard-GEO?

Modern web infrastructure sits at a crossroads: websites must remain visible to **Search Engines** (`Googlebot`, `Bingbot`) and **AI Answer Engines** (`GPTBot`, `ClaudeBot`, `PerplexityBot`, `OAI-SearchBot`) while protecting origin bandwidth and crawl budgets from aggressive scrapers (`Bytespider`, `CCBot`) and broken endpoints.

## Key Features

- **Search & AI Bot Log Analytics (`crawlguard_geo/log_analyzer.py`)**
  - Parses Nginx/Apache Combined Access Logs to separate **Search Engines**, **AI Crawlers**, and **Generic Bots**.
  - Measures per-bot request volume, bandwidth (KB), HTTP `2xx/3xx/4xx/5xx` distribution, unique IP count, and **Crawl-Budget Waste %**.
  - Generates automated edge alerts when high-value bots hit `5xx` errors or waste `>=30%` of requests on broken URLs.
- **robots.txt & llms.txt Policy Auditor (`crawlguard_geo/policy_auditor.py`)**
  - Detects accidental global `Disallow: /` traps, missing `Sitemap:` declarations, and missing explicit AI crawler rules.
  - Validates `/llms.txt` Markdown structure and curated canonical links for AI agent discovery.
- **Executive Reporting (`crawlguard_geo/reporter.py`)**
  - Outputs clean **Markdown**, **JSON**, and dark-theme **HTML** reports.

## Project Structure

```text
crawlguard-geo/
├── main.py
├── crawlguard_geo/
│   ├── __init__.py
│   ├── cli.py
│   ├── log_analyzer.py
│   ├── policy_auditor.py
│   └── reporter.py
├── samples/
│   ├── access.log
│   ├── llms.txt
│   └── robots.txt
├── tests/
│   └── test_crawlguard.py
├── LICENSE
└── README.md
```

## Quick Start

Requires **Python 3.10+** (pure standard library — zero external dependencies).

```bash
python3 main.py \
  --access-log samples/access.log \
  --robots samples/robots.txt \
  --llms samples/llms.txt \
  --out-md geo_report.md \
  --out-html geo_report.html \
  --out-json geo_report.json
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
