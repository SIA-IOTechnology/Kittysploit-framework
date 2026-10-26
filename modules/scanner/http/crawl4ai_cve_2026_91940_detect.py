#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect crawl4ai API CVE-2026-91940 exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "crawl4ai CVE-2026-91940 detect",
        "description": (
            "Detects crawl4ai HTTP API (POST /crawl) vulnerable to CVE-2026-91940 "
            "(untrusted PDFContentScrapingStrategy image_save_dir arbitrary write < 0.9.3)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-91940"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-91940",
            "https://github.com/BiiTts/CVE-2026-91940-crawl4ai-Arbitrary-File-Write",
        ],
        "tags": ["scanner", "crawl4ai", "file-write", "cve-2026-91940"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": [
                    "exploits/multi/http/crawl4ai_cve_2026_91940_file_write",
                ],
            },
        },
    }

    port = OptPort(11235, "crawl4ai API port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)
    api_path = OptString("/health", "Health or docs path", required=False)

    def run(self):
        for path in (str(self.api_path or "/health"), "/", "/docs"):
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or int(response.status_code or 0) != 200:
                continue
            body = (response.text or "").lower()
            if "crawl" in body or "crawl4ai" in body:
                self.set_info(
                    severity="critical",
                    reason="crawl4ai-style API responding",
                    path=path,
                )
                return True

        crawl_probe = self.http_request(
            method="POST",
            path="/crawl",
            headers={"Content-Type": "application/json"},
            data='{"urls":["http://127.0.0.1/"]}',
            allow_redirects=False,
        )
        if crawl_probe and int(crawl_probe.status_code or 0) in (400, 401, 422, 500):
            self.set_info(severity="critical", reason="POST /crawl endpoint present", path="/crawl")
            return True
        return False
