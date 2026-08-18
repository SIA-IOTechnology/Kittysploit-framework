#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-14620 — webpack-dev-server open-editor CSRF detection via Sec-Fetch probes."""

from __future__ import annotations

from urllib.parse import urlencode

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "webpack-dev-server CVE-2026-14620 open-editor CSRF detect",
        "description": (
            "Detects CVE-2026-14620 in webpack-dev-server <= 5.2.5: cross-site GET "
            "/webpack-dev-server/open-editor?fileName= reaches launchEditor(). "
            "Probes cors and no-cors Sec-Fetch combinations; vulnerable when cors "
            "cross-site returns HTTP 200 while no-cors cross-site is blocked (403)."
        ),
        "author": ["Jorge González Milla (Pig-Tail)", "KittySploit Team"],
        "cve": ["CVE-2026-14620"],
        "severity": "medium",
        "tags": [
            "web",
            "scanner",
            "webpack",
            "webpack-dev-server",
            "csrf",
            "dev-server",
            "cve-2026-14620",
        ],
        "references": [
            "https://github.com/webpack/webpack-dev-server/security/advisories/GHSA-f5vj-f2hx-8m93",
            "https://www.cve.org/CVERecord?id=CVE-2026-14620",
            "https://github.com/Pig-Tail/security-research/tree/master/CVE-2026-14620-webpack-dev-server",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 0.8,
            "noise": 0.35,
            "value": 0.9,
            "requires": {
                "tech_hints_any": ["webpack", "webpack-dev-server", "dev"],
            },
            "chain": {
                "produces_capabilities": [
                    {
                        "capability": "csrf_primitive",
                        "from_detail": "webpack-dev-server open-editor",
                    },
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "browser_auxiliary/check/webpack_dev_server_cve_2026_14620_csrf",
                ],
            },
        },
    }

    file_name = OptString(
        "kittysploit-probe",
        "Benign fileName query value (may trigger launchEditor on vulnerable hosts)",
        required=False,
    )
    skip_endpoint_probe = OptBool(
        False,
        "Skip initial /webpack-dev-server presence check",
        required=False,
        advanced=True,
    )

    def _host_header(self) -> str:
        host = str(getattr(self, "host", "") or "").strip()
        port = int(getattr(self, "port", 80) or 80)
        ssl = bool(getattr(self, "ssl", False))
        default = 443 if ssl else 80
        if host and port != default:
            return f"{host}:{port}"
        return host or "localhost"

    def _open_editor_path(self) -> str:
        query = urlencode({"fileName": str(self.file_name or "kittysploit-probe").strip()})
        return f"/webpack-dev-server/open-editor?{query}"

    def _probe(self, sec_fetch_mode: str, sec_fetch_dest: str = "empty") -> dict:
        headers = {
            "Host": self._host_header(),
            "Origin": "https://evil.example",
            "Sec-Fetch-Mode": sec_fetch_mode,
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Dest": sec_fetch_dest,
        }
        response = self.http_request(
            method="GET",
            path=self._open_editor_path(),
            headers=headers,
            allow_redirects=False,
            timeout=max(int(self.timeout or 10), 5),
        )
        if not response:
            return {"ok": False, "error": "no response"}
        body = (response.text or "")[:240]
        blocked = (
            int(response.status_code or 0) == 403
            and "Cross-Origin request blocked" in (response.text or "")
        )
        return {
            "ok": True,
            "status": int(response.status_code or 0),
            "blocked": blocked,
            "body_preview": body,
        }

    def _endpoint_present(self) -> bool:
        response = self.http_request(
            method="GET",
            path="/webpack-dev-server",
            allow_redirects=False,
            timeout=max(int(self.timeout or 10), 5),
        )
        if not response:
            return False
        return int(response.status_code or 0) in (200, 301, 302, 304)

    def check(self):
        if not bool(self.skip_endpoint_probe) and not self._endpoint_present():
            sockjs = self.http_request(
                method="GET",
                path="/sockjs-node/info",
                allow_redirects=False,
                timeout=max(int(self.timeout or 10), 5),
            )
            if not sockjs or int(sockjs.status_code or 0) != 200:
                return {
                    "vulnerable": False,
                    "reason": "webpack-dev-server surface not detected",
                    "confidence": "medium",
                }

        cors = self._probe("cors", "empty")
        if not cors.get("ok"):
            return {
                "vulnerable": False,
                "reason": cors.get("error") or "cors probe failed",
                "confidence": "low",
            }

        no_cors = self._probe("no-cors", "script")
        navigate = self._probe("navigate", "iframe")

        if cors.get("status") == 200:
            return {
                "vulnerable": True,
                "reason": (
                    "cross-site cors fetch reaches open-editor (HTTP 200); "
                    "launchEditor CSRF likely (CVE-2026-14620)"
                ),
                "confidence": "high",
                "evidence": {
                    "cors_fetch": cors,
                    "no_cors_fetch": no_cors,
                    "navigate_iframe": navigate,
                },
            }

        if cors.get("blocked") or cors.get("status") == 403:
            return {
                "vulnerable": False,
                "reason": "cross-site open-editor blocked (HTTP 403; likely >= 5.2.6)",
                "confidence": "high",
                "evidence": {
                    "cors_fetch": cors,
                    "no_cors_fetch": no_cors,
                    "navigate_iframe": navigate,
                },
            }

        return {
            "vulnerable": False,
            "reason": f"unexpected cors probe status HTTP {cors.get('status')}",
            "confidence": "low",
            "evidence": {
                "cors_fetch": cors,
                "no_cors_fetch": no_cors,
                "navigate_iframe": navigate,
            },
        }

    def run(self):
        print_status("CVE-2026-14620 — webpack-dev-server open-editor CSRF detect")
        print_info(f"Endpoint: {self._open_editor_path()}")
        print_warning("Probes may invoke launchEditor() on vulnerable instances")

        result = self.check()
        evidence = result.get("evidence") or {}

        for label, key in (
            ("cors fetch", "cors_fetch"),
            ("no-cors script", "no_cors_fetch"),
            ("navigate iframe", "navigate_iframe"),
        ):
            vector = evidence.get(key) or {}
            if vector.get("ok"):
                print_info(f"{label}: HTTP {vector.get('status')}")

        if result.get("vulnerable"):
            self.set_info(
                severity="medium",
                reason=result.get("reason") or "CVE-2026-14620 open-editor CSRF",
                path=self._open_editor_path(),
            )
            print_success(result.get("reason") or "Vulnerable")
            return True

        print_warning(result.get("reason") or "Not vulnerable or inconclusive")
        return False
