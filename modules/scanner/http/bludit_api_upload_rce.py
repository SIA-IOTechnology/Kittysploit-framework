#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import random
import string


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Bludit CMS < 3.18.4 - API Unrestricted File Upload (CVE-2026-25099)",
        "description": (
            "Detects CVE-2026-25099 on Bludit when a valid API token is provided. "
            "Optional active probe uploads a harmless .txt file to confirm unrestricted upload behavior."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "cve": "CVE-2026-25099",
        "modules": [
            "exploits/php/bludit_api_upload_rce",
        ],
        "tags": ["web", "scanner", "bludit", "file-upload", "cve-2026-25099"],
        "references": [
            "CVE-2026-25099",
            "https://github.com/bludit/bludit/archive/refs/tags/3.18.2.zip",
            "https://www.bludit.com/",
        ],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    token = OptString("", "Bludit API token", required=True)
    active_probe = OptBool(
        False,
        "Send harmless .txt upload to confirm unrestricted upload",
        required=False,
    )
    verify_upload_access = OptBool(
        True,
        "After active probe, verify uploaded file is reachable",
        required=False,
        advanced=True,
    )

    def _looks_like_bludit(self, body: str) -> bool:
        if not body:
            return False
        text = body.lower()
        return (
            "bludit" in text
            or "/bl-content/" in text
            or "bl-kernel" in text
            or "generator\" content=\"bludit" in text
        )

    def _get_page_key(self):
        try:
            r = self.http_request(
                method="GET",
                path="/api/pages",
                params={"token": self.token},
                timeout=12,
            )
            if not r:
                return None, "No response from /api/pages"
            if r.status_code != 200:
                return None, f"/api/pages returned HTTP {r.status_code}"

            data = r.json()
            if data.get("data") and len(data["data"]) > 0:
                page_key = data["data"][0].get("key")
                if page_key:
                    return page_key, ""
            return None, "Token valid request but no pages found"
        except Exception as e:
            return None, f"Failed parsing /api/pages response: {e}"

    def _fingerprint_bludit(self) -> bool:
        try:
            r = self.http_request(method="GET", path="/", allow_redirects=True, timeout=10)
            if not r:
                return False
            return self._looks_like_bludit(r.text or "")
        except Exception:
            return False

    def _active_upload_probe(self, page_key: str):
        probe_name = "".join(random.choices(string.ascii_lowercase, k=8)) + ".txt"
        probe_content = "kittysploit-cve-2026-25099-probe"

        try:
            r = self.http_request(
                method="POST",
                path=f"/api/files/{page_key}",
                data={"token": self.token},
                files={"file": (probe_name, probe_content, "text/plain")},
                timeout=15,
            )
            if not r:
                return {"ok": False, "reason": "No response from upload endpoint", "probe_url": ""}
            if r.status_code != 200:
                return {
                    "ok": False,
                    "reason": f"Upload endpoint returned HTTP {r.status_code}",
                    "probe_url": "",
                }

            data = r.json()
            if str(data.get("status")) != "0":
                return {
                    "ok": False,
                    "reason": f"Upload rejected by API (status={data.get('status')})",
                    "probe_url": "",
                }

            probe_url = f"/bl-content/uploads/pages/{page_key}/{probe_name}"
            if not self.verify_upload_access:
                return {"ok": True, "reason": "Upload accepted by API endpoint", "probe_url": probe_url}

            vr = self.http_request(method="GET", path=probe_url, timeout=10)
            if not vr or vr.status_code != 200:
                return {
                    "ok": True,
                    "reason": "Upload accepted but probe file not directly reachable",
                    "probe_url": probe_url,
                }
            if probe_content in (vr.text or ""):
                return {
                    "ok": True,
                    "reason": "Upload accepted and uploaded probe is reachable",
                    "probe_url": probe_url,
                }
            return {"ok": True, "reason": "Upload accepted and probe path reachable", "probe_url": probe_url}
        except Exception as e:
            return {"ok": False, "reason": f"Active upload probe failed: {e}", "probe_url": ""}

    def check(self):
        page_key, reason = self._get_page_key()
        if not page_key:
            return {"vulnerable": False, "reason": reason, "confidence": "low", "probe_url": ""}

        has_fp = self._fingerprint_bludit()
        base_reason = (
            f"Valid API token and page key found ({page_key}). "
            f"Bludit fingerprint={'yes' if has_fp else 'no'}"
        )
        if not self.active_probe:
            return {
                "vulnerable": True,
                "reason": f"{base_reason}. Passive check only; set active_probe true to confirm upload behavior.",
                "confidence": "medium",
                "probe_url": "",
            }

        probe = self._active_upload_probe(page_key)
        if probe["ok"]:
            return {
                "vulnerable": True,
                "reason": f"{base_reason}. Active probe: {probe['reason']}",
                "confidence": "high",
                "probe_url": probe["probe_url"],
            }
        return {
            "vulnerable": False,
            "reason": f"{base_reason}. Active probe failed: {probe['reason']}",
            "confidence": "medium",
            "probe_url": "",
        }

    def run(self):
        result = self.check()
        if not result.get("vulnerable"):
            return False

        severity = "critical" if result.get("confidence") == "high" else "high"
        self.set_info(
            severity=severity,
            cve="CVE-2026-25099",
            reason=result.get("reason", "Bludit API unrestricted upload behavior detected"),
            confidence=result.get("confidence", "unknown"),
            probe_url=result.get("probe_url", ""),
            active_probe=bool(self.active_probe),
        )
        return True
