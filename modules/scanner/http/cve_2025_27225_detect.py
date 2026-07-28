#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TRUfusion Enterprise versions 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TRUfusion Enterprise <= 7.10.4.0 - Admin Contact Portal Detection',
        'description': 'TRUfusion Enterprise versions 7.10.4.0 and earlier contained a vulnerability that allowed unauthenticated access to the Internal Admin Contact Page, resulting in the disclosure of PII (including partner and contact names).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'trufusion', 'auth-bypass', 'vuln'],
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
            'https://github.com/MrTuxracer/advisories/blob/master/CVEs/CVE-2025-27225.txt',
            'https://www.rcesecurity.com/2025/09/when-audits-fail-four-critical-pre-auth-vulnerabilities-in-trufusion-enterprise/',
            'https://docs.rocketsoftware.com/bundle/trufusion_rn_71031/page/kwg1743156415157.html',
        ],
        'cve': 'CVE-2025-27225',
    }

    def run(self):
        r = self.http_request(method="GET", path='/trufusionPortal/jsp/internal_admin_contact_login.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('Partner :', 'page.logout()', 'trufusionPortal',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="TRUfusion Enterprise <= 7.10.4.0 - Admin Contact Portal detected",
                path='/trufusionPortal/jsp/internal_admin_contact_login.jsp',
            )
            return True
        return False

