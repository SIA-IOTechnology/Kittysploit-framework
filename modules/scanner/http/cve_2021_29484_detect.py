#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ghost CMS 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ghost CMS <=4.32 - Cross-Site Scripting Detection',
        'description': 'Ghost CMS 4.0.0 to 4.3.2 contains a DOM cross-site scripting vulnerability. An unused endpoint added during the development of 4.0.0 allows attackers to gain access by getting logged-in users to click a link containing malicious code.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'ghost', 'node.js', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/TryGhost/Ghost/security/advisories/GHSA-9fgx-q25h-jxrg',
            'https://www.npmjs.com/package/ghost',
            'https://forum.ghost.org/t/critical-security-update-available-for-ghost-4-x/22290',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-29484',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-29484',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ghost/preview', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('XMLHttpRequest.prototype.open = XMLHttpRequest.prototype.send', 'top.postMessage(',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Ghost CMS <=4.32 - Cross-Site Scripting detected",
                path='/ghost/preview',
            )
            return True
        return False

