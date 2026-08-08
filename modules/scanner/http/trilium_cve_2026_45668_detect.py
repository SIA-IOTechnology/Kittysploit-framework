#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Trilium Notes CVE-2026-45668 safe-import path traversal RCE surface."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Trilium Notes CVE-2026-45668 Safe Import RCE Detect",
        "description": (
            "Detects CVE-2026-45668 in Trilium Notes (TriliumNext) desktop <= 0.102.1: safe import "
            "fails to strip docName path traversal and code-note XSS, enabling RCE in the "
            "nodeIntegration Electron renderer. Fingerprints /bootstrap for triliumVersion "
            "(fixed in 0.102.2)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-45668"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-45668",
            "https://www.cve.org/CVERecord?id=CVE-2026-45668",
        ],
        "modules": ["exploits/multi/http/trilium_cve_2026_45668_rce"],
        "tags": [
            "web",
            "scanner",
            "trilium",
            "electron",
            "xss",
            "path-traversal",
            "rce",
            "cve-2026-45668",
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
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["trilium"],
                "endpoint_pattern_any": ["/bootstrap"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "safe-import docName traversal"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/trilium_cve_2026_45668_rce",
                ],
            },
        },
    }

    port = OptPort(37840, "Trilium desktop HTTP API port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    def run(self):
        base = (self.path or "/").rstrip("/")
        bootstrap_path = f"{base}/bootstrap" if base else "/bootstrap"
        try:
            response = self.http_request(
                method="GET",
                path=bootstrap_path,
                session=True,
                allow_redirects=False,
                timeout=int(self.timeout or 15),
            )
        except Exception as exc:
            print_status(f"CVE-2026-45668 probe failed: {exc.__class__.__name__}")
            return False

        if not response or int(response.status_code or 0) != 200:
            return False

        body, err = parse_json_response(response)
        if err or not body:
            return False

        csrf = body.get("csrfToken")
        version = str(body.get("triliumVersion") or "")
        if not csrf:
            return False

        match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
        if not match:
            print_status(f"CVE-2026-45668 Trilium API seen but version unknown ({version!r})")
            self.set_info(
                severity="medium",
                reason="Trilium /bootstrap reachable; version not parsed",
                cve="CVE-2026-45668",
                path=bootstrap_path,
                trilium_version=version,
            )
            return True

        ver_t = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        if ver_t >= (0, 102, 2):
            print_status(f"CVE-2026-45668 patched Trilium {version} (>= 0.102.2)")
            return False

        reason = f"CVE-2026-45668: Trilium {version} < 0.102.2 (safe-import RCE)"
        print_status(f"CVE-2026-45668 vuln=True version={version}")
        self.set_info(
            severity="critical",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-45668",
            path=bootstrap_path,
            trilium_version=version,
        )
        return True
