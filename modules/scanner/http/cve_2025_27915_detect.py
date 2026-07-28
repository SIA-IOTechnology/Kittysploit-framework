#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Zimbra Collaboration Suite versions vulnerable to CVE-2025-27915, a stored XSS vulnerability in the Cl."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zimbra - Cross-Site Scripting via ICS Files Detection',
        'description': 'Detects Zimbra Collaboration Suite versions vulnerable to CVE-2025-27915, a stored XSS vulnerability in the Classic Web Client due to insufficient sanitization of HTML content in ICS files. When a user views an email with a malicious ICS entry, embedded JavaScript executes via an ontoggle event inside a details tag, allowing attackers to perform unauthorized actions like email redirection and data exfiltration.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'zimbra', 'xss', 'ics', 'kev', 'vkev'],
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
            'https://wiki.zimbra.com/wiki/Security_Center',
            'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-27915',
        ],
        'cve': 'CVE-2025-27915',
    }

    def run(self):
        path = '/js/zimbraMail/share/model/ZmSettings.js'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Zimbra Collaboration Suite',)
        header_any = ('application/x-javascript',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='Zimbra - Cross-Site Scripting via ICS Files detected',
                path=path,
            )
            return True
        return False

