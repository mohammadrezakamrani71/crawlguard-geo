"""Unit tests for CrawlGuard-GEO."""

import unittest

from crawlguard_geo.log_analyzer import analyze_access_log
from crawlguard_geo.policy_auditor import audit_llms_txt, audit_robots_txt
from crawlguard_geo.reporter import render_html_report, render_json_report, render_markdown_report


class TestCrawlGuardGeo(unittest.TestCase):
    def test_log_analysis_classifies_ai_and_search_bots(self) -> None:
        sample = "\n".join(
            [
                '66.249.66.1 - - [26/Nov/2026:10:00:00 +0000] "GET / HTTP/2.0" 200 1000 "-" "Googlebot/2.1"',
                '20.171.207.1 - - [26/Nov/2026:10:00:01 +0000] "GET /llms.txt HTTP/2.0" 200 500 "-" "GPTBot/1.2"',
                '54.183.22.9 - - [26/Nov/2026:10:00:02 +0000] "GET /api HTTP/2.0" 503 200 "-" "PerplexityBot/1.0"',
            ]
        )
        res = analyze_access_log(sample)
        self.assertEqual(res.total_requests, 3)
        self.assertEqual(res.total_bot_requests, 3)
        names = {b.name for b in res.bots}
        self.assertEqual(names, {"Googlebot", "GPTBot", "PerplexityBot"})
        self.assertTrue(any("5xx" in a for a in res.alerts))

    def test_robots_and_llms_policy_audit(self) -> None:
        robots = "User-agent: *\nDisallow: /admin/\nUser-agent: GPTBot\nAllow: /\nSitemap: https://example.org/sitemap.xml\n"
        llms = "# Docs\n- [A](https://example.org/a)\n- [B](https://example.org/b)\n"
        findings = audit_robots_txt(robots) + audit_llms_txt(llms)
        self.assertTrue(all(f.status == "PASS" for f in findings))

    def test_reports_render(self) -> None:
        res = analyze_access_log('1.2.3.4 - - [26/Nov/2026:10:00:00 +0000] "GET / HTTP/2.0" 200 1024 "-" "ClaudeBot/1.0"')
        pol = audit_robots_txt("User-agent: *\nDisallow: /\n")
        self.assertIn("CrawlGuard-GEO", render_markdown_report(res, pol))
        self.assertIn("<!DOCTYPE html>", render_html_report(res, pol))
        self.assertIn("ClaudeBot", render_json_report(res, pol))


if __name__ == "__main__":
    unittest.main()
