#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Confluence OGNL pre-auth indicators (CVE-2022-26134 fingerprint)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


OGNL_MARKERS = (
    "ognl",
    "classloader",
    "ognlexception",
    "propertyaccessor",
    "xwork",
    "atlassian",
    "confluence",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Confluence Pre-Auth OGNL Detection",
        "description": (
            "Safe fingerprint for Confluence OGNL injection surface "
            "(CVE-2022-26134 indicator — no weaponized payload)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2022-26134",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-26134",
        ],
        "tags": ["web", "scanner", "confluence", "ognl", "cve", "atlassian"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': True,
        'produces': ['tech_hints', 'risk_signals'],
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

    def run(self):
        probes = (
            "/%24%7Bclass.forName('java.lang.String')%7D/",
            "/wiki/%24%7B7*7%7D/",
            "/confluence/%24%7B7*7%7D/",
        )
        for path in probes:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            body = (r.text or "").lower()
            if any(marker in body for marker in OGNL_MARKERS):
                self.set_info(
                    severity="high",
                    reason="Confluence OGNL evaluation indicator detected",
                    path=path,
                    cve="CVE-2022-26134",
                )
                return True
        return False
